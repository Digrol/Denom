// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.tlspsk;

import java.util.Map;
import org.denom.*;
import org.denom.log.ILog;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;
import static org.denom.tlspsk.TlsConst.*;

/**
 * TLS-PSK-сессия.
 */
public class TlsPSKSession
{
	/**
	 * Версия протокола TLS, см. TlsConst.Protocol
	 */
	public int protocolVersion = Protocol.TLSv1_2;

	/**
	 * Выбранный для сессии CipherSuite
	 */
	public int cipherSuite = 0;

	/**
	 * Случайка клиента [32 байта]
	 */
	public Binary clientRandom = null;

	/**
	 * Случайка сервера [32 байта]
	 */
	public Binary serverRandom = null;

	/**
	 * Extension: encrypt_then_mac (22).
	 * RFC 7366.
	 * Шифровать сообщение, потом добавлять MAC.
	 */
	public boolean isEncryptThenMAC = false;

	/**
	 * Extension: truncated_hmac (4).
	 * RFC 4366.
	 * Урезать размер вычисляемого HMAC до 10 байт.
	 */
	public boolean isTruncateHMac = false;

	/**
	 * Максимальный размер открытых данных (до шифрования), передаваемых в одном Record Fragment.
	 * Можно уменьшить расширением max_fragment_length (1).
	 */
	public int plainLimit  = 16384; // 2 ^ 14
	/**
	 * Максимальный размер зашифрованных данных, передаваемых в одном Record Fragment.
	 * Вычисляется от plaintextLimit и выбранного cipherSuite.
	 */
	public int cryptLimit = plainLimit; // 2 ^ 14

	/**
	 * Накапливаем сообщения для вычисления хеша и MAC в handshake-сообщениях Finished.
	 */
	public Binary handshakeMessages = Bin().reserve( 256 );

	/**
	 * Идентификатор для вывода PSK.
	 */
	public Binary identity;

	/**
	 * Pre-Shared Key.
	 */
	public Binary psk;

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
	public boolean isHandshakeDone = false;


	protected ILog log;


	// -----------------------------------------------------------------------------------------------------------------
	public TlsPSKSession( ILog log )
	{
		MUST( log != null, "Log must be not null" );
		this.log = log;
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
	public void addHandshakeMessage( final Binary handshakeMsg )
	{
		handshakeMessages.add( handshakeMsg );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Клиент сгенерировал, либо сервер принял ClientHello, берём из него и запоминаем параметры: рандом клиента.
	 */
	public void gotClientHello( final TlsHelloClient clientHello )
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

}
