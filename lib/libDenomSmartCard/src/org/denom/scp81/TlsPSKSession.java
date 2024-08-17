// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.scp81;

import java.util.*;
import java.util.function.*;

import org.denom.*;
import org.denom.log.Colors;
import org.denom.log.ILog;
import org.denom.log.LogDummy;
import org.denom.scp81.TlsConst.*;
import org.denom.scp81.http.HttpReq;
import org.denom.scp81.http.HttpResp;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * TLS-PSK-сессия.
 */
public class TlsPSKSession
{
	protected final static int COLOR_BLUE1 = 0xFF40A0FF;
	protected final static int COLOR_BLUE2 = 0xFF36BCFF;
	protected final static int COLOR_BLUE3 = 0xFF10F0FF;
	protected final static int COLOR_PINK1 = 0xFFF050F5;
	protected final static int COLOR_PINK2 = 0xFFF090F0;
	protected final static int COLOR_PINK3 = 0xFFFFC0FF;

	/**
	 * Версия протокола TLS, см. TlsConst.Protocol
	 */
	protected int protocolVersion = Protocol.TLSv1_2;

	/**
	 * Выбранный для сессии CipherSuite
	 */
	protected int cipherSuite = 0;

	/**
	 * Случайка клиента [32 байта]
	 */
	protected Binary clientRandom = null;

	/**
	 * Случайка сервера [32 байта]
	 */
	protected Binary serverRandom = null;

	/**
	 * Extension: encrypt_then_mac (22).
	 * RFC 7366.
	 * Шифровать сообщение, потом добавлять MAC.
	 */
	protected boolean isEncryptThenMAC = false;

	/**
	 * Extension: truncated_hmac (4).
	 * RFC 4366.
	 * Урезать размер вычисляемого HMAC до 10 байт.
	 */
	protected boolean isTruncateHMac = false;

	/**
	 * Максимальный размер открытых данных (до шифрования), передаваемых в одном Record Fragment.
	 * Можно уменьшить расширением max_fragment_length (1).
	 */
	protected int plainLimit  = 16384; // 2 ^ 14
	/**
	 * Максимальный размер зашифрованных данных, передаваемых в одном Record Fragment.
	 * Вычисляется от plaintextLimit и выбранного cipherSuite.
	 */
	protected int cryptLimit = plainLimit; // 2 ^ 14

	/**
	 * Накапливаем сообщения для вычисления хеша и MAC в handshake-сообщениях Finished.
	 */
	protected Binary handshakeMessages = Bin().reserve( 256 );

	/**
	 * Идентификатор для вывода PSK.
	 */
	protected Binary identity;

	/**
	 * Pre-Shared Key.
	 */
	protected Binary psk;

	/**
	 * Шифрователь Record-ов.
	 */
	private TlsPSKCrypt encoder = null;

	/**
	 * Расшифровыватель Record-ов.
	 */
	private TlsPSKCrypt decoder = null;

	/**
	 * True - если Handshake проведён до конца и можно передавать и принимать прикладные данные
	 */
	protected boolean handshakeDone = false;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Функция возвращает PSK для заданного identity.
	 * @return null - если PSK для этого identity неизвестен. 
	 */
	protected Function<Binary, Binary> funcGetPSK;

	/**
	 * Через этот функтор передаём байтовый поток.
	 */
	protected Consumer<Binary> funcSendData;

	/**
	 * Вызывается после расшифровывания фрагмента с прикладными данными для обработки прикладных данных.
	 */
	protected Consumer<Binary> funcRecievedAppData;

	// -----------------------------------------------------------------------------------------------------------------
	protected ILog log = new LogDummy();

	protected static final int STATE_WAIT_HELLO = 1;
	protected static final int STATE_WAIT_KEY_EXCHANGE = 2;
	protected static final int STATE_WAIT_HELLO_DONE = 3;
	protected static final int STATE_WAIT_CHANGE_CIPHER = 10;
	protected static final int STATE_WAIT_FINISHED = 11;
	protected static final int STATE_HANDSHAKE_DONE = 20;
	protected static final int STATE_ERROR = -1;
	protected int state;

	protected Binary inBuf = Bin().reserve( 16384 + 5 );
	protected Binary recordBody = Bin();
	protected Binary bufHandshake = Bin();

	protected boolean isServer;

	protected Map<Integer, Binary> extensions = new HashMap<>();
	protected Arr<Integer> cipherSuites = new Arr<>();

	protected int colorRecv1;
	protected int colorRecv2;
	protected int colorRecv3;
	protected int colorSend1;
	protected int colorSend2;
	protected int colorSend3;

	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKSession( boolean isServer )
	{
		this.isServer = isServer;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKSession setLog( ILog log )
	{
		MUST( log != null, "Log must be not null" );
		this.log = log;

		if( isServer )
		{
			colorSend1 = COLOR_BLUE1;
			colorSend2 = COLOR_BLUE2;
			colorSend3 = COLOR_BLUE3;
			colorRecv1 = COLOR_PINK1;
			colorRecv2 = COLOR_PINK2;
			colorRecv3 = COLOR_PINK3;
		}
		else
		{
			colorSend1 = COLOR_PINK1;
			colorSend2 = COLOR_PINK2;
			colorSend3 = COLOR_PINK3;
			colorRecv1 = COLOR_BLUE1;
			colorRecv2 = COLOR_BLUE2;
			colorRecv3 = COLOR_BLUE3;
		}

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKSession addCipherSuite( int cipherSuite )
	{
		cipherSuites.add( cipherSuite );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKSession addExtension( int extensionType, final Binary extData )
	{
		extensions.put( extensionType, extData );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKSession setGetPSK( Function<Binary, Binary> funcGetPSK )
	{
		Objects.requireNonNull( funcGetPSK );
		this.funcGetPSK = funcGetPSK;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKSession setSendData( Consumer<Binary> funcSendData )
	{
		Objects.requireNonNull( funcSendData );
		this.funcSendData = funcSendData;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKSession setRecievedAppData( Consumer<Binary> funcRecievedAppData )
	{
		Objects.requireNonNull( funcRecievedAppData );
		this.funcRecievedAppData = funcRecievedAppData;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void clearHandshakeData()
	{
		clientRandom = null;
		serverRandom = null;
		cipherSuite = 0;

		isEncryptThenMAC = false;
		isTruncateHMac = false;

		plainLimit = 16384;
		cryptLimit = plainLimit;

		handshakeMessages = Bin();

		encoder = null;
		decoder = null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean isHandshakeDone()
	{
		return handshakeDone;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Передать прикладные данные по TLS-соединению. Данные нарезаются на фрагменты.
	 */
	public void sendAppData( final Binary data )
	{
		MUST( handshakeDone, "Cannot write application data until handshake completed." );

		int offset = 0;
		int len = data.size();
		while( len > 0 )
		{
			int partSize = Math.min( len, this.plainLimit );
			sendRecord( ContentType.APPLICATION_DATA, data.slice( offset, partSize ) );
			offset += partSize;
			len -= partSize;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Передать HTTP-запрос.
	 */
	public void sendHttpReq( final HttpReq req )
	{
		log.writeln( Colors.DARK_GRAY, "HTTP Request:" );
		log.writeln( HttpReq.COLOR, req.toString() );
		sendAppData( req.toBin() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Передать HTTP-ответ.
	 */
	public void sendHttpResp( final HttpResp resp )
	{
		log.writeln( Colors.DARK_GRAY, "HTTP Response:" );
		log.writeln( HttpResp.COLOR, resp.toString() );
		sendAppData( resp.toBin() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void sendCloseNotify()
	{
		try
		{
			sendRecord( ContentType.ALERT, Bin(1, 1).add( Alert.CLOSE_NOTIFY ) );
		}
		catch (Throwable ex) {}
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void addHandshakeMessage( final Binary handshakeMsg )
	{
		handshakeMessages.add( handshakeMsg );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Клиент сгенерировал, либо сервер принял ClientHello, берём из него и запоминаем параметры: рандом клиента.
	 */
	protected void gotClientHello( final TlsHelloClient clientHello )
	{
		protocolVersion = clientHello.protocol;
		clientRandom = clientHello.random;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сервер сгенерировал, либо клиент принял ServerHello, берём из него и запоминаем все параметры и расширения.
	 */
	public void gotServerHello( final TlsHelloServer serverHello )
	{
		protocolVersion = serverHello.protocol;
		serverRandom = serverHello.random;
		cipherSuite = serverHello.cipherSuite;

		// Применяем расширения
		for( Map.Entry<Integer, Binary> entry : serverHello.extensions.entrySet() )
		{
			Binary data = entry.getValue();

			switch( entry.getKey() )
			{
				case Extension.MAX_FRAGMENT_LENGTH:
					MUST( data.size() == 1, Alert.ILLEGAL_PARAMETER, "Wrong extension" );
					int maxFragmLen = data.get( 0 );
					MUST( (maxFragmLen >= 1) && (maxFragmLen <= 4), Alert.ILLEGAL_PARAMETER ) ;
					plainLimit = 1 << (8 + maxFragmLen);
					break;

				case Extension.ENCRYPT_THEN_MAC:
					MUST( data.size() == 0, Alert.ILLEGAL_PARAMETER );
					isEncryptThenMAC = true;
					break;

				case Extension.TRUNCATED_HMAC:
					MUST( data.size() == 0, Alert.ILLEGAL_PARAMETER );
					isTruncateHMac = true;
					break;
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void initEncrypter( boolean isServerKeys )
	{
		MUST( psk != null, "TLS PSK Session: psk not set" );
		encoder = TlsPSKCrypt.createEncoder( this, isServerKeys );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void initDecrypter( boolean isServerKeys )
	{
		MUST( psk != null, "TLS PSK Session: psk not set" );
		decoder = TlsPSKCrypt.createDecoder( this, isServerKeys );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить криптограмму для Finished-сообщения
	 * @param isFromServer: true - криптограмма от сервера, false - от клиента.
	 */
	public Binary calcVerifyData( boolean isFromServer )
	{
		TlsPSKCrypt tlsCrypt = (decoder != null) ? decoder : encoder;
		return tlsCrypt.calcVerifyData( isFromServer );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary encodeRecord( int contentType, final Binary recordBody )
	{
		if( encoder == null)
			return recordBody;
		
		return encoder.encode( contentType, recordBody );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary decodeRecord( int recordType, final Binary encryptedBody )
	{
		if( decoder == null)
			return encryptedBody;
		
		return decoder.decode( recordType, encryptedBody );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void appendIncomingData( final Binary data )
	{
		int offset = 0;
		while( offset < data.size() )
		{
			int partSize = Math.min( this.cryptLimit + 5, data.size() - offset );
			inBuf.add( data, offset, partSize );
			offset += partSize;

			while( processIncomingData() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private boolean processIncomingData()
	{
		try
		{
			if( inBuf.size() < 5 ) // Ждём в буфере заголовок TLS-фрагмента
				return false;
			
			int recordType = inBuf.get( 0 );
			int tlsVersion = inBuf.getU16( 1 );
			int fragmentLength = inBuf.getU16( 3 );
			MUST( fragmentLength <= this.cryptLimit, Alert.RECORD_OVERFLOW );
			
			int fullLen = 5 + fragmentLength;
			if( inBuf.size() < fullLen ) // Ждём в буфере TLS-фрагмент целиком
				return false;
				
			recordBody.assign( inBuf, 5, fragmentLength );
			
			log.writeln( Colors.DARK_GRAY, "---------------------------------" );
			log.writeln( colorRecv1, String.format( Locale.US, "recv [%4d] : %02X %04X %04X %s",
					fullLen, recordType, tlsVersion, fragmentLength, recordBody.Hex()) );

			inBuf.assign( inBuf, fullLen, inBuf.size() - fullLen );

			// Decrypt
			recordBody = decodeRecord( recordType, recordBody );

			if( handshakeDone )
				log.writeln( colorRecv2, "    Decrypted: " + recordBody.Hex() );

			MUST( recordBody.size() <= this.plainLimit, Alert.RECORD_OVERFLOW );

			switch( recordType )
			{
				case ContentType.ALERT:
					processRecordAlert( recordBody ); break;

				case ContentType.HANDSHAKE:
					processRecordHandshake( recordBody ); break;
				
				case ContentType.APPLICATION_DATA:
					MUST( handshakeDone, Alert.UNEXPECTED_MESSAGE );
					funcRecievedAppData.accept( recordBody );
					break;

				case ContentType.CHANGE_CIPHER:
					processChangeCipher( recordBody );
					break;

				default: throw new Ex( Alert.UNEXPECTED_MESSAGE );
			}

			return true;
		}
		catch( Ex ex )
		{
			sendFatal( ex.code );
			state = STATE_ERROR;
			throw new Ex( "Wrong TLS" );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void onHandshakeMessage( int type, final Binary message, final Binary data ) {}
	
	// -----------------------------------------------------------------------------------------------------------------
	protected void processRecordHandshake( final Binary recBody )
	{
		MUST( recBody.size() > 0, Alert.DECODE_ERROR );
		bufHandshake.add( recBody );

		// We need the first 4 bytes, they contain type and length of the message.
		while( bufHandshake.size() >= 4 )
		{
			int type = bufHandshake.get( 0 );
			int dataLen = bufHandshake.getU24( 1 );
			MUST( dataLen <= 32768, Alert.RECORD_OVERFLOW );

			int fullLen = 4 + dataLen;
			if( bufHandshake.size() < fullLen )
				break; // Wait full message

			Binary message = bufHandshake.first( fullLen );
			Binary data = message.slice( 4, message.size() - 4 );

			// Убираем из буфера обрабатываемое сообщение
			bufHandshake.assign( bufHandshake, fullLen, bufHandshake.size() - fullLen );

			log.writeln( colorRecv2, String.format("    Handshake msg:  type: %02X (%s), data:  %s",
					type, HandshakeType.toStr( type ), message.last( message.size() - 4 ).Hex()) );

			onHandshakeMessage(type, message, data);
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void processChangeCipher( final Binary recBody )
	{
		log.writeln( colorRecv2, "    Change Cipher Spec" );
		MUST( recBody.size() == 1, Alert.DECODE_ERROR );
		MUST( recBody.get( 0 ) == 0x01, Alert.DECODE_ERROR );
		MUST( bufHandshake.size() == 0, Alert.UNEXPECTED_MESSAGE );

		MUST( state == STATE_WAIT_CHANGE_CIPHER, Alert.UNEXPECTED_MESSAGE );
		this.initDecrypter( !isServer );
		state = STATE_WAIT_FINISHED;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void processRecordAlert( final Binary recBody )
	{
		MUST( recBody.size() == 2, Alert.DECODE_ERROR );

		log.writeln( colorRecv2, String.format( "ALERT:  type:  %02X,  description:  %02X (%s)",
				recBody.get( 0 ), recBody.get( 1 ), Alert.toStr( recBody.get( 1 ) ) ) );

		throw new Ex( recBody.asU16(), "Alert recieved" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void sendRecord( int recordType, final Binary recordData )
	{
		MUST( recordData.size() <= this.plainLimit );

		Binary cipheredData = encodeRecord( recordType, recordData );

		Binary rec = new Binary().reserve( recordData.size() + 5 + 16 );
		rec.add( recordType );
		rec.addU16( this.protocolVersion );
		rec.addU16( cipheredData.size() );
		rec.add( cipheredData );

		log.writeln( colorSend1, String.format( Locale.US, "send [%4d] : %02X %04X %04X %s\n",
				rec.size(), recordType, this.protocolVersion, cipheredData.size(), cipheredData.Hex() ) );

		MUST( funcSendData != null, "funcSendData == null" );
		funcSendData.accept( rec );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void finishHandshake()
	{
		log.writeln( colorSend2, "    Change Cipher Spec" );
		sendRecord( ContentType.CHANGE_CIPHER, Bin(1, 1) );

		initEncrypter( isServer );

		sendHandshakeMsg( HandshakeType.FINISHED, calcVerifyData( isServer ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void sendHandshakeMsg( int msgType, final Binary body )
	{
		Binary b = new Binary().reserve( 64 );
		b.add( msgType );        // HandshakeType msg_type
		b.addU24( body.size() ); // uint24 length
		b.add( body );           // body

		log.writeln( colorSend2, String.format("    Handshake msg:  type: %02X (%s), data:  %s",
				msgType, HandshakeType.toStr( msgType ), body.Hex()) );

		addHandshakeMessage( b );

		sendRecord( ContentType.HANDSHAKE, b );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void sendFatal( int alert )
	{
		try
		{
			log.writeln( colorSend2, String.format( "FATAL ALERT:  description:  %02X (%s)",
					alert, Alert.toStr(alert ) ) );

			sendRecord( ContentType.ALERT, Bin(1, 2).add( alert ) );
		}
		catch( Throwable ee ) {}
	}
}
