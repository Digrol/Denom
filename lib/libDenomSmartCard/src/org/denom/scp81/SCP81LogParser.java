// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.scp81;

import org.denom.*;
import org.denom.log.*;
import org.denom.scp81.http.*;

import static org.denom.Binary.Bin;

/**
 * Расшифровывание логов TLS-PSK-сессии.
 */
public class SCP81LogParser
{
	public Binary psk;
	public ILog log;

	MyServerSession serverSession;
	MyClientSession clientSession;

	// -----------------------------------------------------------------------------------------------------------------
	private class MyServerSession extends TlsPSKServerSession
	{
		protected void onClientHello( final Binary message, final Binary data )
		{
			TlsHelloClient clientHello = new TlsHelloClient( data );
			log.write( colorRecv3, clientHello.toString() );
			gotClientHello( clientHello );
			clientSession.gotClientHello( clientHello );
		}

		protected void onClientKeyExchange( final Binary message, final Binary data )
		{
			identity = data.slice( 2, data.getU16( 0 ) );
			log.writeln( colorRecv3, "        Client Identity: " + identity.Hex() + ", as String:  " + identity.asUTF8() );
			state = STATE_WAIT_CHANGE_CIPHER;
		}

		protected void onClientFinished( final Binary message, final Binary data )
		{
			log.writeln( colorRecv3, "        Client Verify data: " + data.Hex() );
			handshakeDone = true;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private class MyClientSession extends TlsPSKClientSession
	{
		public MyClientSession()
		{
			super( 0, Bin(), Bin() );
		}
		
		protected void onServerHello( final Binary message, final Binary data )
		{
			TlsHelloServer serverHello = new TlsHelloServer( data );
			log.write( colorRecv3, serverHello.toString() );

			serverSession.gotServerHello( serverHello );
			gotServerHello( serverHello );
		}
		
		protected void onServerKeyExchange( final Binary message, final Binary data )
		{
			Binary pskIdentityHint = data.slice( 2, data.getU16( 0 ) );

			String str = "";
			try { str = pskIdentityHint.asUTF8(); } catch (Throwable e) {}
			log.writeln( colorRecv3, "       IDENTITY HINT:  " + pskIdentityHint.Hex() + ",    as String:  " + str );
		}
		
		protected void onServerHelloDone( final Binary message, final Binary data )
		{
			log.writeln( colorRecv3, "       SERVER HELLO DONE" );
			state = STATE_WAIT_CHANGE_CIPHER;
		}
		
		protected void onServerFinished( Binary data )
		{
			log.writeln( colorRecv3, "        Server Verify data: " + data.Hex() );
			clientSession.handshakeDone = true;
		}
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public SCP81LogParser( final Binary psk, ILog log )
	{
		this.psk = psk;
		this.log = log;
		
		serverSession = new MyServerSession();
		serverSession.setLog( log );
		serverSession.psk = psk;
		HttpReqParser httpReqParser = new HttpReqParser().setOnHttpReq( (req) -> {} ).setLog( log );
		serverSession.setRecievedAppData( httpReqParser::append );

		clientSession = new MyClientSession();
		clientSession.setLog( log );
		clientSession.psk = psk;
		HttpRespParser httpRespParser = new HttpRespParser().setOnHttpResp( (resp) -> {} ).setLog( log );
		clientSession.setRecievedAppData( httpRespParser::append );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить данные, поступившие от карты на сервер.
	 */
	public void fromClient( Binary dataFromClient )
	{
		serverSession.appendIncomingData( dataFromClient );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void fromClient( String dataFromClientHex )
	{
		fromClient( Bin( dataFromClientHex ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить данные, поступившие с сервера на карту.
	 */
	public void fromServer( Binary dataFromServer )
	{
		clientSession.appendIncomingData( dataFromServer );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void fromServer( String dataFromServerHex )
	{
		fromServer( Bin(dataFromServerHex) );
	}
}
