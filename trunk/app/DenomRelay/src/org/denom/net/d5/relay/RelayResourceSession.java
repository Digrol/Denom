// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5.relay;

import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.util.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.format.*;
import org.denom.net.*;
import org.denom.d5.*;
import org.denom.d5.relay.*;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

// -----------------------------------------------------------------------------------------------------------------
public class RelayResourceSession extends D5ResponseSession
{
	protected final Relay relay;
	protected final int resourceTimeoutSec;

	// Большинство полей, передаваемых в ответе на WHO_ARE_YOU, нужно запоминать.
	// Чтобы не заводить в этом классе аналогичные поля, просто сохраняем в сессии ответ на команду.
	protected ResponseWhoAreYou resourceInfo = null;

	// Resource serial number in Relay.
	protected long handle = 0;

	// Connected users to this Resource
	protected Map<Long, RelayUserSession> bindedUsers = new HashMap<>();

	protected RelayAuth relayAuth = null;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * For creating instances by method newInstance.
	 */
	public RelayResourceSession( Relay relay, ILog log )
	{
		super( relay.options.sessionBufSize, log );
		this.relay = relay;
		this.resourceTimeoutSec = relay.options.resource.timeoutSec;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public RelayResourceSession newInstance( TCPServer tcpServer, SocketChannel clientSocket )
	{
		RelayResourceSession newSession = new RelayResourceSession( relay, log, tcpServer, clientSocket );
		log.writeln( "Accept on Resource port. Remote Address: " + newSession.remoteAddress );
		relay.doWork( newSession::commandWhoAreYou );
		return newSession;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected RelayResourceSession( Relay relay, ILog log, TCPServer tcpServer, SocketChannel clientSocket )
	{
		super( relay.options.sessionBufSize, log, tcpServer, clientSocket );
		this.relay = relay;
		this.resourceTimeoutSec = relay.options.resource.timeoutSec;

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
	private Binary emptyBin = new Binary();
	public void commandEnumCommands()
	{
		sendCommand( D5Command.ENUM_COMMANDS, emptyBin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected void processResponse( D5Response response )
	{
		relay.doWork( () -> dispatch( response ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Got Response from Resource.
	 * Worker threads.
	 */
	private void dispatch( D5Response response )
	{
		try
		{
			if( response.status != D5Response.STATUS_OK )
			{
				THROW( response.status, String.format( "(0x%08X) %s", response.status, response.data.asUTF8() ) );
			}

			switch( response.code + 0x20000000 )
			{
				case D5Command.ENUM_COMMANDS     : break;
				case RelayCommand.WHO_ARE_YOU    : responseWhoAreYou( response ); break;
				case RelayCommand.RELAY_SIGN     : responseRelaySign( response ); break;
				case RelayCommand.SEND:
				case RelayCommand.SEND_ENCRYPTED : responseSend( response ); break;
				default:
					throw new Ex("Unknown Response");
			}
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.RED_I, ex.toString() );
			this.close();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * При подключении ресурса отправляем ему WHO ARE YOU, чтобы он представился.
	 */
	private void commandWhoAreYou()
	{
		this.relayAuth = new RelayAuth( relay.options.relayKey );
		sendCommand( RelayCommand.WHO_ARE_YOU, relayAuth.requestWhoAreYou() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Обработка ответа на команду WHO ARE YOU.
	 */
	private void responseWhoAreYou( D5Response response )
	{
		// Получили от ресурса ответ на команду WHO ARE YOU, но Relay команду не посылал
		MUST( relayAuth != null, "Protocol Error: Got 'WHO ARE YOU' response" );

		this.resourceInfo = relayAuth.responseWhoAreYou( response.data );
		MUST( resourceInfo.resourceName.length() <= relay.options.resource.nameMaxLen,
				"Protocol Error: responseWhoAreYou: too long Name" );
		MUST( resourceInfo.resourceDescription.length() <= relay.options.resource.descriptionMaxLen,
				"Protocol Error: responseWhoAreYou: too long description" );

		// Ресурс аутентифицирован, запоминаем его идентификаторы, добавляем в список ресурсов.

		handle = relay.lastResourceID.incrementAndGet();

		synchronized( relay.resources )
		{
			// Закрываем сессию, если было старую подключение с таким же публичным ключом.
			RelayResourceSession oldSession = relay.resources.get( resourceInfo.resourcePublicKey );
			if( oldSession != null )
				oldSession.close();

			relay.resources.put( resourceInfo.resourcePublicKey, this );
		}

		log.writeln( "Resource connected."
				+ "\nPublicKey: " + resourceInfo.resourcePublicKey.Hex()
				+ "\nName: " + resourceInfo.resourceName
				+ "\nID: " + Num_Bin( handle, 8 ).Hex()
				+ "\nRemote address: " + remoteAddress.toString() );

		// Отправить ресурсу подпись от Relay-а.
		sendCommand( RelayCommand.RELAY_SIGN, relayAuth.requestRelaySign() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Обработка ответа на команду WHO ARE YOU.
	 */
	private void responseRelaySign( D5Response response )
	{
		// Получили от ресурса ответ на команду RELAY SIGN, но Relay команду не посылал
		MUST( relayAuth != null, "Protocol Error: Got 'REALY SIGN' response" );
		relayAuth = null;
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
			response.data.setLong( 0, this.handle );
			response.index = response.data.getIntBE( 8 );
			response.data.setInt( 8, 0 );
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

		if( resourceInfo != null )
		{
			synchronized( relay.resources )
			{
				relay.resources.remove( resourceInfo.resourcePublicKey );
			}

			log.writeln( "Resource disconnected."
					+ "\nPublicKey: " + resourceInfo.resourcePublicKey.Hex()
					+ "\nName: " + resourceInfo.resourceName
					+ "\nHandle: " + Num_Bin( handle, 8 ).Hex() );
		}
		
		log.writeln( "Resource connection closed. Remote address: " + remoteAddress.toString() );
	}

}