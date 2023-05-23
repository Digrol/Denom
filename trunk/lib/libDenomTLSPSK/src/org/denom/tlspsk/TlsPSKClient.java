// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.tlspsk;

import java.util.*;

import org.denom.*;
import org.denom.format.LV;
import org.denom.log.ILog;
import org.denom.net.SocketClient;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

import static org.denom.tlspsk.TlsConst.*;

// -----------------------------------------------------------------------------------------------------------------
public class TlsPSKClient extends TlsPSKPeer
{
	private Map<Integer, Binary> extensions = new HashMap<>();
	private Arr<Integer> cipherSuites = new Arr<>();

	// -----------------------------------------------------------------------------------------------------------------
	// Handshake States
	private static final short STATE_WAIT_HELLO = 1;
	private static final short STATE_WAIT_KEY_EXCHANGE = 2;
	private static final short STATE_WAIT_HELLO_DONE = 3;
	private static final short STATE_WAIT_CHANGE_CIPHER = 4;
	private static final short STATE_WAIT_FINISHED = 5;

	private short state = -1;

	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKClient( int protocolVersion, Binary identity, Binary psk, ILog log )
	{
		super( log );
		session.protocolVersion = protocolVersion;
		session.identity = identity.clone();
		session.psk = psk.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKClient addCipherSuite( int cipherSuite )
	{
		cipherSuites.add( cipherSuite );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKClient addExtension( int extensionType, final Binary extData )
	{
		extensions.put( extensionType, extData );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void connect( String host, int port )
	{
		socketClient = new SocketClient( 10 );
		socketClient.connect( host, port );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void doHandshake()
	{
		MUST( socketClient != null, "do connect first" );
		MUST( !session.isHandshakeDone, "Handshake done already" );

		TlsHelloClient hello = new TlsHelloClient( session.protocolVersion, Bin().randomSecure( 32 ), Bin(), cipherSuites, extensions );
		session.gotClientHello( hello );
		log.write( COLOR_SEND3, hello.toString() );
		sendHandshakeMsg( HandshakeType.CLIENT_HELLO, hello.toBin() );
		this.state = STATE_WAIT_HELLO;

		while( !session.isHandshakeDone )
		{
			readRecord();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void onHandshakeMessage( Binary message, int type, final Binary data )
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
	private void onServerHello( final Binary message, final Binary data )
	{
		MUST( state == STATE_WAIT_HELLO, Alert.UNEXPECTED_MESSAGE );

		session.addHandshakeMessage( message );

		TlsHelloServer serverHello = new TlsHelloServer( data );
		log.write( COLOR_RECV3, serverHello.toString() );

		MUST( serverHello.protocol == session.protocolVersion, Alert.PROTOCOL_VERSION );

		MUST( cipherSuites.contains( serverHello.cipherSuite ), Alert.ILLEGAL_PARAMETER );

		serverHello.extensions.forEach( (extension, extData) -> {
			MUST( extData.equals( this.extensions.get( extension ) ), Alert.ILLEGAL_PARAMETER );
		} );

		session.gotServerHello( serverHello );

		this.state = STATE_WAIT_KEY_EXCHANGE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void onServerKeyExchange( final Binary message, final Binary data )
	{
		MUST( state == STATE_WAIT_KEY_EXCHANGE, Alert.UNEXPECTED_MESSAGE );

		session.addHandshakeMessage( message );

		int hintLen = data.getU16( 0 );
		MUST( data.size() == (2 + hintLen), Alert.DECODE_ERROR );
		Binary psk_identity_hint = data.slice( 2, hintLen );

		String str = "";
		try { str = psk_identity_hint.asUTF8(); } catch (Throwable e) {}
		log.writeln( COLOR_RECV3, "         IDENTITY HINT:  " + psk_identity_hint.Hex() + ",    as String:  " + str );

		this.state = STATE_WAIT_HELLO_DONE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void onServerHelloDone( final Binary message, final Binary data )
	{
		MUST( (state == STATE_WAIT_KEY_EXCHANGE) || (state == STATE_WAIT_HELLO_DONE), Alert.UNEXPECTED_MESSAGE );
		MUST( data.size() == 0, Alert.DECODE_ERROR );

		session.addHandshakeMessage( message );

		sendHandshakeMsg( HandshakeType.CLIENT_KEY_EXCHANGE, LV.LV2( session.identity ) );
		sendChangeCipherSpec();
		session.initEncrypter( false );
		sendHandshakeMsg( HandshakeType.FINISHED, session.calcVerifyData( false ) );

		state = STATE_WAIT_CHANGE_CIPHER;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected void onChangeCipher()
	{
		MUST( state == STATE_WAIT_CHANGE_CIPHER, Alert.UNEXPECTED_MESSAGE );
		session.initDecrypter( true );
		state = STATE_WAIT_FINISHED;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void onServerFinished( Binary data )
	{
		MUST( state == STATE_WAIT_FINISHED, Alert.UNEXPECTED_MESSAGE );

		MUST( data.size() == 12, Alert.DECODE_ERROR );
		MUST( session.calcVerifyData( true ).equals( data ), Alert.DECRYPT_ERROR );

		state = -1;
		session.handshakeMessages = null;
		session.isHandshakeDone = true;
	}
	
}
