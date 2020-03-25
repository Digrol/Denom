// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5.relay;

import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.util.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.format.BinParser;
import org.denom.net.*;
import org.denom.net.d5.*;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

// -----------------------------------------------------------------------------------------------------------------
public class RelayResourceSession extends D5ResponseSession
{
	protected final Relay relay;
	protected final int resourceTimeoutSec;


	protected String name = "";

	// Resource serial number in Relay.
	protected long id = 0;


	Map<Long, RelayUserSession> bindedUsers = new HashMap<>();


	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * For creating instances by method newInstance.
	 */
	public RelayResourceSession( Relay relay, ILog log )
	{
		super( relay.options.sessionBufSize, log );
		this.relay = relay;
		this.resourceTimeoutSec = relay.options.resourceTimeoutSec;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public RelayResourceSession newInstance( TCPServer tcpServer, SocketChannel clientSocket )
	{
		RelayResourceSession s = new RelayResourceSession( relay, log, tcpServer, clientSocket );
		log.writeln( "Accept on Resource port. Remote Address: " + s.remoteAddress );

		relay.getWorkerExecutor().execute( () -> s.sendCommand( RelayCmd.WHO_ARE_YOU, Bin() ) );

		return s;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected RelayResourceSession( Relay relay, ILog log, TCPServer tcpServer, SocketChannel clientSocket )
	{
		super( relay.options.sessionBufSize, log, tcpServer, clientSocket );
		this.relay = relay;
		this.resourceTimeoutSec = relay.options.resourceTimeoutSec;
		
		try
		{
			socket.socket().setSoTimeout( resourceTimeoutSec * 1000 );
		}
		catch( SocketException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean isAlive()
	{
		try
		{
			int timeout = socket.socket().getSoTimeout();
			socket.socket().setSoTimeout( 2 * 1000 );
			sendCommand( D5Command.ENUM_COMMANDS, Bin() );
			socket.socket().setSoTimeout( timeout );
			return true;
		}
		catch( Throwable ex )
		{
			return false;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected void processResponse( D5Response response )
	{
		relay.getWorkerExecutor().execute( () -> dispatch( response ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void dispatch( D5Response response )
	{
		try
		{
			switch( response.code + 0x20000000 )
			{
				case RelayCmd.WHO_ARE_YOU: responseWhoAreYou( response ); break;
				case RelayCmd.SEND:        responseSend( response ); break;
				default:
					break;
			}
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.RED_I, ex.toString() );
			this.close();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void responseWhoAreYou( D5Response response )
	{
		BinParser sbParser = new BinParser( response.data, 0 );

		// Resource names himself
		String resourceName = sbParser.getString();

		MUST( !resourceName.isEmpty() && (resourceName.length() <= 256), "responseWhoAreYou: Wrong resource name length" );

		synchronized( relay.resources )
		{
			RelayResourceSession oldSession = relay.resources.get( resourceName );
			if( oldSession != null )
			{
				if( oldSession.getSocket().isOpen() )
				{
					throw new Ex( "responseWhoAreYou: Resource name busy: " + resourceName );
				}
				oldSession.close();
			}
			MUST( relay.resources.put( resourceName, this ) == null, "responseWhoAreYou: Resource name busy: " + resourceName );
		}

		id = relay.lastResourceID.incrementAndGet();

		log.writeln( "Resource connected. Name: " + resourceName + ". ID: " + Num_Bin( id, 8 ).Hex()
				+ ". Remote address: " + remoteAddress.toString() );

		name = resourceName;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void cmdSend( RelayUserSession userSession, D5Command command )
	{
		synchronized( bindedUsers )
		{
			bindedUsers.putIfAbsent( userSession.id, userSession );
		}
		this.sendCommand( command );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void responseSend( D5Response response )
	{
		BinParser bp = new BinParser( response.data, 0 );
		long userHandle = bp.getLong();

		RelayUserSession userSession = null;
		synchronized( bindedUsers )
		{
			userSession = bindedUsers.get( userHandle );
		}

		if( userSession == null )
			return;
		
		if( userSession.getSocket().isOpen() )
		{
			response.data.setLong( 0, this.id );
			response.index = response.data.getIntBE( 8 );
			response.data.set( 8, 0 );
			userSession.sendResponse( response );
		}
		else
		{
			synchronized( bindedUsers )
			{
				userSession = bindedUsers.remove( userHandle );
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void close()
	{
		super.close();

		synchronized( relay.resources )
		{
			relay.resources.remove( name );
		}

		log.writeln( "Resource disconnected. Name: " + name + ". ID: " + Num_Bin( id, 8 ).Hex()
				+ ". Remote address: " + remoteAddress.toString() );
	}

//	// -----------------------------------------------------------------------------------------------------------------
//	public void keepAliveResources()
//	{
//		relay.getWorkerExecutor().execute( () ->
//		{
//			synchronized( relay.resources )
//			{
//				long now = System.nanoTime();
//				long intervalNanos = resourceTimeoutSec * 1_000_000_000L;
//
//				Iterator<D5ResponseSession> iter = relay.resources.values().iterator();
//				while( iter.hasNext() )
//				{
//					RelayResourceSession session = (RelayResourceSession)iter.next();
//					
//					long diffTime = now - session.lastActivity;
//					if( (diffTime < 0) || (diffTime > intervalNanos) )
//					{
//						if( !session.isAlive() )
//						{
//							session.close();
//							session.log.writeln( Colors.WHITE, "Resource '" + 
//									session.remoteAddress.getHostName() + "' inactive. Disconnected." );
//							iter.remove();
//						}
//					}
//				}
//			}
//		} );
//	}

}