// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.tlspsk;

import java.io.*;
import java.util.*;

import org.denom.*;
import org.denom.format.LV;
import org.denom.log.ILog;
import org.denom.net.SocketClient;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;
import static org.denom.tlspsk.TlsConst.*;

// -----------------------------------------------------------------------------------------------------------------
public class TlsPSKServer extends TlsPSKPeer
{
	private Map<Binary, Binary> pskMap;
	private Binary pskHint;

	// -----------------------------------------------------------------------------------------------------------------
	// Connection States
	protected static final int STATE_WAIT_HELLO = 1;
	protected static final int STATE_WAIT_KEY_EXCHANGE = 2;
	protected static final int STATE_WAIT_CHANGE_CIPHER = 3;
	protected static final int STATE_WAIT_FINISHED = 3;

	private int state = -1;


	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param pskList  Identity -> PSK
	 */
	public TlsPSKServer( Map<Binary, Binary> pskMap, Binary pskHint, ILog log )
	{
		super( log );
		this.pskMap = pskMap;
		this.pskHint = pskHint.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void acceptClient( SocketClient client ) throws IOException
	{
		MUST( !session.isHandshakeDone, "Handshake done already" );

		socketClient = client;

		state = STATE_WAIT_HELLO;
		while( !session.isHandshakeDone )
		{
			readRecord();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected void onHandshakeMessage( Binary message, int type, final Binary data )
	{
		switch( type )
		{
			case HandshakeType.CLIENT_HELLO:        onClientHello( message, data ); break;
			case HandshakeType.CLIENT_KEY_EXCHANGE: onClientKeyExchange( message, data ); break;
			case HandshakeType.FINISHED:            onFinished( message, data ); break;
			default:
				throw new Ex( Alert.UNEXPECTED_MESSAGE );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Приём Client Hello.
	 * Отправка ServerHello, ServerKeyExchange, ServerHelloDone.
	 */
	private void onClientHello( final Binary message, final Binary data )
	{
		MUST( state == STATE_WAIT_HELLO, Alert.UNEXPECTED_MESSAGE );

		session.addHandshakeMessage( message );

		TlsHelloClient clientHello = new TlsHelloClient( data );
		session.gotClientHello( clientHello );
		log.write( COLOR_RECV3, clientHello.toString() );

		session.protocolVersion = clientHello.protocol;

		// Cipher suite
		// Сервер поддерживает все алгоритмы из списка констант, определяем по пустой строке, чтобы не делать отдельный метод.
		int cipherSuite = 0;
		for( int suite : clientHello.cipherSuites )
		{
			if( !CipherSuite.toStr( suite ).isEmpty() )
			{
				cipherSuite = suite;
				break;
			}
		}
		MUST( cipherSuite > 0, Alert.ILLEGAL_PARAMETER );

		// Extensions
		for( int extension : clientHello.extensions.keySet() )
		{
			// Сервер поддерживает все расширения из списка констант, определяем по пустой строке, чтобы не делать отдельный метод.
			if( Extension.toStr( extension ).isEmpty() )
				clientHello.extensions.remove( extension ); // Unsupported extension

			if( (extension == Extension.ENCRYPT_THEN_MAC)
				&&( (cipherSuite == CipherSuite.PSK_NULL_SHA) || (cipherSuite == CipherSuite.PSK_NULL_SHA256) ) )
				clientHello.extensions.remove( extension );
		}


		TlsHelloServer serverHello = new TlsHelloServer( clientHello.protocol, Bin().randomSecure( 32 ),
				Bin(), cipherSuite, clientHello.extensions );
		session.gotServerHello( serverHello );
		log.write( COLOR_SEND3, serverHello.toString() );

		sendHandshakeMsg( HandshakeType.SERVER_HELLO, serverHello.toBin() );
		sendHandshakeMsg( HandshakeType.SERVER_KEY_EXCHANGE, LV.LV2( pskHint ) );
		sendHandshakeMsg( HandshakeType.SERVER_HELLO_DONE, Bin() );

		this.state = STATE_WAIT_KEY_EXCHANGE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void onClientKeyExchange( final Binary message, final Binary data )
	{
		MUST( state == STATE_WAIT_KEY_EXCHANGE, Alert.UNEXPECTED_MESSAGE );

		session.addHandshakeMessage( message );

		int identityLen = data.getU16( 0 );
		MUST( data.size() == (2 + identityLen), Alert.DECODE_ERROR );

		session.identity = data.slice( 2, identityLen );
		session.psk = pskMap.get( session.identity );
		MUST( session.psk != null, Alert.ILLEGAL_PARAMETER, "No PSK for identity" );

		this.state = STATE_WAIT_CHANGE_CIPHER;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected void onChangeCipher()
	{
		MUST( state == STATE_WAIT_CHANGE_CIPHER, Alert.UNEXPECTED_MESSAGE );
		session.initDecrypter( false );
		state = STATE_WAIT_FINISHED;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void onFinished( final Binary message, final Binary data )
	{
		MUST( state == STATE_WAIT_FINISHED, Alert.UNEXPECTED_MESSAGE );

		MUST( data.size() == 12, Alert.DECODE_ERROR );
		MUST( session.calcVerifyData( false ).equals( data ), Alert.DECRYPT_ERROR );

		session.addHandshakeMessage( message );

		sendChangeCipherSpec();
		session.initEncrypter( true );
		sendHandshakeMsg( HandshakeType.FINISHED, session.calcVerifyData( true ) );

		state = -1;
		session.handshakeMessages = null;
		session.isHandshakeDone = true;
	}
}
