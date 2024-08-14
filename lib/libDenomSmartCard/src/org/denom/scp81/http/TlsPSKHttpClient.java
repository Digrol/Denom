// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.scp81.http;

import org.denom.Binary;
import org.denom.log.*;
import org.denom.net.SocketClient;
import org.denom.scp81.TlsPSKClientSession;

import static org.denom.Binary.Bin;

/**
 * Отправляет HTTP Request на сервер через TlsPSKClient, принимает и парсит ответ.
 */
public class TlsPSKHttpClient
{
	private final SocketClient socketClient;
	private final HttpRespParser respParser;
	private final TlsPSKClientSession session;
	private HttpResp curResp;
	Binary buf = Bin();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param tlsPskClient - should already be connected to server and handshake Done.
	 */
	public TlsPSKHttpClient( SocketClient socketClient, TlsPSKClientSession session, ILog logHTTP )
	{
		this.socketClient = socketClient;
		this.session = session;

		respParser = new HttpRespParser().setLog( logHTTP );
		session.setRecievedAppData( respParser::append );
		session.setSendData( socketClient::write );
		respParser.setOnHttpResp( (r) -> curResp = r );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void doHandshake()
	{
		session.startHandshake();

		while( !session.isHandshakeDone() )
		{
			socketClient.readSome( buf, 1024 );
			session.appendIncomingData( buf );
			buf.clear();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public synchronized HttpResp send( HttpReq req )
	{
		session.sendHttpReq( req );
		curResp = null;
		buf.clear();
		while( curResp == null )
		{
			socketClient.readSome( buf, 1000 );
			session.appendIncomingData( buf );
			buf.clear();
		}
		return curResp;
	}
}
