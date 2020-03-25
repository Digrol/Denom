// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5.relay;

import java.util.*;
import java.nio.channels.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.format.*;
import org.denom.net.TCPServer;
import org.denom.net.d5.*;

import static org.denom.Ex.MUST;
import static org.denom.Binary.*;

// -----------------------------------------------------------------------------------------------------------------
public class RelayUserSession extends D5CommandSession
{
	public long id = 0;

	private final Relay relay;

	// Resource ID -> Resource Session
	private Map<Long, RelayResourceSession> bindedResources = new HashMap<>();

	// -----------------------------------------------------------------------------------------------------------------
	public RelayUserSession( Relay relay, ILog log )
	{
		super( relay.options.sessionBufSize, log );
		this.relay = relay;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public RelayUserSession newInstance( TCPServer tcpProcessor, SocketChannel clientSocket )
	{
		return new RelayUserSession( relay, log, tcpProcessor, clientSocket );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected RelayUserSession( Relay relay, ILog log, TCPServer tcpProcessor, SocketChannel clientSocket )
	{
		super( relay.options.sessionBufSize, log, tcpProcessor, clientSocket );
		this.relay = relay;
		id = relay.lastUserID.incrementAndGet();
		log.writeln( "User Session created. ID: " + Num_Bin( id, 8 ).Hex() + ". Remote address: " + remoteAddress.toString() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void processCommand( D5Command command )
	{
		relay.getWorkerExecutor().execute( () -> processCommandImpl( command ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void processCommandImpl( D5Command command )
	{
		Binary data = Bin();
		int status = D5Response.STATUS_OK;
		
		try
		{
			data = dispatchCommand( command );
		}
		catch( Ex ex )
		{
			status = D5Response.STATUS_UNKNOWN_ERROR;
			if( (ex.code & 0xE0000000) == 0xE0000000 )
			{
				status = ex.code;
			}
			data.fromUTF8( ex.getMessage() );
		}
		catch( Throwable ex )
		{
			status = D5Response.STATUS_UNKNOWN_ERROR;
			data.fromUTF8( ex.toString() );
		}

		if( data != null )
		{
			D5Response response = new D5Response();
			response.code   = command.code - 0x20000000;
			response.status = status;
			response.index  = command.index;
			response.data = data;
			sendResponse( response );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary dispatchCommand( D5Command command )
	{
		switch( command.code )
		{
			case D5Command.ENUM_COMMANDS      : return cmdEnumCommands();
			case D5Command.EXECUTE_TOKEN      : return cmdExecuteToken( command.data );

			case RelayCmd.LIST_RESOURCES      : return cmdListResources( command );
			case RelayCmd.IS_RESOURCE_PRESENT : return cmdIsResourcePresent( command );
			case RelayCmd.SEND_TO             : return cmdSendTo( command );
			case RelayCmd.SEND                : return cmdSend( command );

			default:
				throw new Ex( D5Response.STATUS_COMMAND_NOT_SUPPORTED );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary cmdEnumCommands()
	{
		Binary b = Bin();
		b.addInt( D5Command.ENUM_COMMANDS );
		b.addInt( D5Command.EXECUTE_TOKEN );

		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary cmdExecuteToken( final Binary token )
	{
		relay.executeToken( token );
		return Bin();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private RelayResourceSession findResourceSession( String resourceName )
	{
		RelayResourceSession resourceSession = null;
		// Find resource by Name
		MUST( resourceName.length() > 0, "Resource name is empty" );
		synchronized( relay.resources )
		{
			resourceSession = relay.resources.get( resourceName );
		}

		return resourceSession;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary cmdListResources( D5Command command )
	{
		Binary buf = Bin().reserve( relay.resources.size() * 30 );
		BinBuilder bb = new BinBuilder( buf );

		synchronized( relay.resources )
		{
			bb.appendStringCollection( relay.resources.keySet() );
		}

		return buf;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	private Binary cmdIsResourcePresent( D5Command command )
	{
		BinParser bp = new BinParser( command.data, 0 );
		String resourceName = bp.getString();

		RelayResourceSession resourceSession = findResourceSession( resourceName );
		if( resourceSession == null )
		{
			return Bin( 8 );
		}

		// Add local mapping Handle -> Resource Session
		synchronized( bindedResources )
		{
			bindedResources.putIfAbsent( resourceSession.id, resourceSession );
		}

		return Bin().addLong( resourceSession.id );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Send message to Resource identified by Name.
	 */
	private Binary cmdSendTo( D5Command command )
	{
		BinParser bp = new BinParser( command.data, 0 );
		String resourceName = bp.getString();
		
		RelayResourceSession resourceSession = findResourceSession( resourceName );
		MUST( resourceSession != null, "Resource not found" );

		// Add local mapping Handle -> Resource Session
		synchronized( bindedResources )
		{
			bindedResources.putIfAbsent( resourceSession.id, resourceSession );
		}

		int dataLen = bp.getInt();
		Binary newData = new Binary().reserve( dataLen + 16 );
		BinBuilder bb = new BinBuilder( newData );
		bb.append( this.id );
		bb.append( command.index );
		bb.append( command.data, bp.getOffset(), dataLen );

		command.code = RelayCmd.SEND;
		command.data = newData;
		resourceSession.cmdSend( this, command );

		return null; // Do not send Response now
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Send message to Resource identified by Resource ID.
	 */
	private Binary cmdSend( D5Command command )
	{
		long resourceID = command.data.getLong( 0 );
		int dataLen = command.data.getIntBE( 12 );
		MUST( command.data.size() == (dataLen + 16 ), D5Response.STATUS_WRONG_SYNTAX );

		RelayResourceSession resourceSession = null;
		synchronized( bindedResources )
		{
			resourceSession = bindedResources.get( resourceID );
		}

		MUST( resourceSession != null, "Wrong Resource ID or Resource absent" );

		if( !resourceSession.getSocket().isOpen() )
		{
			synchronized( bindedResources )
			{
				bindedResources.remove( resourceID );
			}
			throw new Ex( "Resource absent" );
		}

		// Replace Resource ID with User ID.
		command.data.setLong( 0, this.id );
		// Save userCommandIndex in body to restore it later, on Resource response.
		command.data.setInt( 8, command.index );
		resourceSession.cmdSend( this, command );

		return null; // Do not send Response now
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void close()
	{
		super.close();
		log.writeln( Colors.CYAN, "User Session closed: " + remoteAddress );
	}

}