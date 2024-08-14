// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5.relay;

import java.util.*;
import java.nio.channels.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.format.*;
import org.denom.net.TCPServer;
import org.denom.d5.*;
import org.denom.d5.relay.*;

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
		relay.doWork( () -> processCommandImpl( command ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processCommandImpl( D5Command command )
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
			case D5Command.ENUM_COMMANDS        : return onCmdEnumCommands();
			case D5Command.EXECUTE_TOKEN        : return onCmdExecuteToken( command.data );

			case RelayCommand.GET_RESOURCE_INFO : return onCmdGetResourceInfo( command );
			case RelayCommand.SEND              : // Обрабатываются одинаково
			case RelayCommand.SEND_ENCRYPTED    : return onCmdSend( command );

			default:
				throw new Ex( D5Response.STATUS_COMMAND_NOT_SUPPORTED );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary onCmdEnumCommands()
	{
		Binary b = Bin();
		b.addInt( D5Command.ENUM_COMMANDS );
		b.addInt( D5Command.EXECUTE_TOKEN );
		b.addInt( RelayCommand.GET_RESOURCE_INFO );
		b.addInt( RelayCommand.SEND );
		b.addInt( RelayCommand.SEND_ENCRYPTED );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary onCmdExecuteToken( final Binary token )
	{
		relay.executeToken( token );
		return Bin();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private RelayResourceSession findResourceSession( Binary resourcePublicKey )
	{
		RelayResourceSession resourceSession = null;
		// Find resource by PublicKey
		MUST( resourcePublicKey.size() == relay.PUBLIC_KEY_SIZE, "Resource PublicKey length wrong" );
		synchronized( relay.resources )
		{
			resourceSession = relay.resources.get( resourcePublicKey );
		}

		return resourceSession;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary onCmdGetResourceInfo( D5Command command )
	{
		BinParser bp = new BinParser( command.data, 0 );
		Binary resourcePublicKey = bp.getBinary();

		ResponseGetResourceInfo resp = new ResponseGetResourceInfo();
		resp.resourceHandle = 0;

		RelayResourceSession resourceSession = findResourceSession( resourcePublicKey );
		if( resourceSession != null )
		{
			resp.resourceHandle = resourceSession.handle;
			resp.resourcePublicKey = resourceSession.resourceInfo.resourcePublicKey;
			resp.resourceName = resourceSession.resourceInfo.resourceName;
			resp.resourceDescription = resourceSession.resourceInfo.resourceDescription;

			// Add local mapping Handle -> Resource Session
			synchronized( bindedResources )
			{
				bindedResources.putIfAbsent( resourceSession.handle, resourceSession );
			}
		}

		return resp.toBin();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Send message to Resource identified by Resource ID.
	 */
	private Binary onCmdSend( D5Command command )
	{
		long resourceID = command.data.getLong( 0 );
		MUST( command.data.size() > 12, D5Response.STATUS_WRONG_SYNTAX );

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