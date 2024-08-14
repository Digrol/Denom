// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.scp81;

import org.denom.*;
import org.denom.format.LV;
import org.denom.scp81.TlsConst.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Принимает входящие данные (байтовый поток) от TLSPSK-клиента, формирует ответы для него (байтовый поток).
 * Накапливает входящие данные в буфер, пока не придёт TLS-фрагмент целиком.
 * Производит handshake, шифрует и расшифровывает прикладные данные.
 */
public class TlsPSKServerSession extends TlsPSKSession
{
	private Binary pskHint = Bin("");

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param pskHint - Подсказка, передаётся клиенту, чтобы он мог понять, какой PSK использовать.
	 */
	public TlsPSKServerSession()
	{
		super( true );
		state = STATE_WAIT_HELLO;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKServerSession setPskHint( final Binary pskHint )
	{
		this.pskHint = pskHint.clone();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void onHandshakeMessage( int type, final Binary message, final Binary data )
	{
		switch( type )
		{
			case HandshakeType.CLIENT_HELLO:        onClientHello( message, data ); break;
			case HandshakeType.CLIENT_KEY_EXCHANGE: onClientKeyExchange( message, data ); break;
			case HandshakeType.FINISHED:            onClientFinished( message, data ); break;
			default:
				throw new Ex( Alert.UNEXPECTED_MESSAGE );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Приём Client Hello.
	 * Отправка ServerHello, ServerKeyExchange, ServerHelloDone.
	 */
	protected void onClientHello( final Binary message, final Binary data )
	{
		MUST( state == STATE_WAIT_HELLO, Alert.UNEXPECTED_MESSAGE );

		addHandshakeMessage( message );

		TlsHelloClient clientHello = new TlsHelloClient( data );
		gotClientHello( clientHello );
		log.write( colorRecv3, clientHello.toString() );

		this.protocolVersion = clientHello.protocol;

		// Cipher suite
		// Сервер поддерживает все алгоритмы из списка констант, определяем по пустой строке, чтобы не делать отдельный метод.
		int cipherSuite = 0;
		for( int suite : clientHello.cipherSuites )
		{
			if( cipherSuites.contains( suite ) )
			{
				cipherSuite = suite;
				break;
			}
		}
		MUST( cipherSuite > 0, Alert.ILLEGAL_PARAMETER );

		// Extensions
		for( int extension : clientHello.extensions.keySet() )
		{
			if( !extensions.containsKey( extension ) )
				clientHello.extensions.remove( extension ); // Unsupported extension

			if( (extension == Extension.ENCRYPT_THEN_MAC)
				&&( (cipherSuite == CipherSuite.PSK_NULL_SHA) || (cipherSuite == CipherSuite.PSK_NULL_SHA256) ) )
				clientHello.extensions.remove( extension );
		}

		TlsHelloServer serverHello = new TlsHelloServer( clientHello.protocol, Bin().randomSecure( 32 ),
				Bin(), cipherSuite, clientHello.extensions );
		gotServerHello( serverHello );

		log.write( colorSend3, serverHello.toString() );
		sendHandshakeMsg( HandshakeType.SERVER_HELLO, serverHello.toBin() );
		sendHandshakeMsg( HandshakeType.SERVER_KEY_EXCHANGE, LV.LV2( pskHint ) );
		sendHandshakeMsg( HandshakeType.SERVER_HELLO_DONE, Bin() );

		this.state = STATE_WAIT_KEY_EXCHANGE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void onClientKeyExchange( final Binary message, final Binary data )
	{
		MUST( state == STATE_WAIT_KEY_EXCHANGE, Alert.UNEXPECTED_MESSAGE );

		addHandshakeMessage( message );

		int identityLen = data.getU16( 0 );
		MUST( data.size() == (2 + identityLen), Alert.DECODE_ERROR );

		this.identity = data.slice( 2, identityLen );
		MUST( funcGetPSK != null, "getPSK not set" );
		this.psk = funcGetPSK.apply( this.identity );
		MUST( this.psk != null, Alert.ILLEGAL_PARAMETER, "No PSK for identity: " + this.identity.Hex());

		this.state = STATE_WAIT_CHANGE_CIPHER;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void onClientFinished( final Binary message, final Binary data )
	{
		MUST( state == STATE_WAIT_FINISHED, Alert.UNEXPECTED_MESSAGE );

		MUST( data.size() == 12, Alert.DECODE_ERROR );
		MUST( calcVerifyData( !isServer ).equals( data ), Alert.DECRYPT_ERROR );

		addHandshakeMessage( message );

		finishHandshake();

		state = STATE_HANDSHAKE_DONE;
		handshakeMessages = null;
		handshakeDone = true;
	}
}
