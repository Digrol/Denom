// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.scp81;

import org.denom.*;
import org.denom.format.LV;
import org.denom.scp81.TlsConst.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
public class TlsPSKClientSession extends TlsPSKSession
{
	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKClientSession( int protocolVersion, Binary identity, Binary psk )
	{
		super( false );

		this.protocolVersion = protocolVersion;
		this.identity = identity.clone();
		this.psk = psk.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void startHandshake()
	{
		MUST( (funcSendData != null) &&  (funcRecievedAppData != null), "Wrong constructed TlsPSKClientSession" );

		MUST( !handshakeDone, "Handshake done already" );

		TlsHelloClient hello = new TlsHelloClient( this.protocolVersion, Bin().randomSecure( 32 ), Bin(), cipherSuites, extensions );
		gotClientHello( hello );
		log.write( colorSend3, hello.toString() );
		sendHandshakeMsg( HandshakeType.CLIENT_HELLO, hello.toBin() );
		this.state = STATE_WAIT_HELLO;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected void onHandshakeMessage( int type, final Binary message, final Binary data )
	{
		switch( type )
		{
			case HandshakeType.SERVER_HELLO:         onServerHello( message, data ); break;
			case HandshakeType.SERVER_KEY_EXCHANGE:  onServerKeyExchange( message, data ); break;
			case HandshakeType.SERVER_HELLO_DONE:    onServerHelloDone( message, data ); break;
			case HandshakeType.FINISHED:             onServerFinished( data ); break;
			default:
				throw new Ex( Alert.UNEXPECTED_MESSAGE );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void onServerHello( final Binary message, final Binary data )
	{
		MUST( state == STATE_WAIT_HELLO, Alert.UNEXPECTED_MESSAGE );

		addHandshakeMessage( message );

		TlsHelloServer serverHello = new TlsHelloServer( data );
		log.write( colorRecv3, serverHello.toString() );

		MUST( serverHello.protocol == this.protocolVersion, Alert.PROTOCOL_VERSION );

		MUST( cipherSuites.contains( serverHello.cipherSuite ), Alert.ILLEGAL_PARAMETER );

		serverHello.extensions.forEach( (extension, extData) -> {
			MUST( extData.equals( this.extensions.get( extension ) ), Alert.ILLEGAL_PARAMETER );
		} );

		gotServerHello( serverHello );

		this.state = STATE_WAIT_KEY_EXCHANGE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void onServerKeyExchange( final Binary message, final Binary data )
	{
		MUST( state == STATE_WAIT_KEY_EXCHANGE, Alert.UNEXPECTED_MESSAGE );

		addHandshakeMessage( message );

		int hintLen = data.getU16( 0 );
		MUST( data.size() == (2 + hintLen), Alert.DECODE_ERROR );
		Binary pskIdentityHint = data.slice( 2, hintLen );

		String str = "";
		try { str = pskIdentityHint.asUTF8(); } catch (Throwable e) {}
		log.writeln( colorRecv3, "         IDENTITY HINT:  " + pskIdentityHint.Hex() + ",    as String:  " + str );

		this.state = STATE_WAIT_HELLO_DONE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void onServerHelloDone( final Binary message, final Binary data )
	{
		MUST( (state == STATE_WAIT_KEY_EXCHANGE) || (state == STATE_WAIT_HELLO_DONE), Alert.UNEXPECTED_MESSAGE );
		MUST( data.size() == 0, Alert.DECODE_ERROR );

		addHandshakeMessage( message );

		sendHandshakeMsg( HandshakeType.CLIENT_KEY_EXCHANGE, LV.LV2( this.identity ) );

		finishHandshake();
		state = STATE_WAIT_CHANGE_CIPHER;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void onServerFinished( Binary data )
	{
		MUST( state == STATE_WAIT_FINISHED, Alert.UNEXPECTED_MESSAGE );

		MUST( data.size() == 12, Alert.DECODE_ERROR );
		MUST( calcVerifyData( !isServer ).equals( data ), Alert.DECRYPT_ERROR );

		state = STATE_HANDSHAKE_DONE;
		handshakeMessages = null;
		handshakeDone = true;
	}
}
