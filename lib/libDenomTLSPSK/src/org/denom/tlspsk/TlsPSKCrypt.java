// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.tlspsk;

import org.denom.*;
import org.denom.crypt.*;
import org.denom.crypt.hash.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;
import static org.denom.tlspsk.TlsConst.*;

public class TlsPSKCrypt
{
	protected static final int COLOR_CRYPT = 0xFF00A030;

	protected ABlockCipher cipher = null;
	protected int blockSize = 0;
	protected boolean useExplicitIV = false;
	protected Binary iv = Bin();

	protected long seqNo = 0;
	protected HMAC hmac;
	protected int hmacSize;

	private Binary masterSecret;

	protected TlsPSKSession session;

	// -----------------------------------------------------------------------------------------------------------------
	private TlsPSKCrypt( TlsPSKSession session, boolean isServerKeys )
	{
		this.session = session;

		session.cryptLimit = session.plainLimit;

		masterSecret = calcMasterSecret( session.psk );
		session.log.writeln( COLOR_CRYPT, "    Master Secret:  " + masterSecret.Hex() );

		int suite = session.cipherSuite;
		// Cipher
		int cipherKeySize = 0;
		if( (suite == CipherSuite.PSK_AES_128_CBC_SHA256) || (suite == CipherSuite.PSK_AES_128_CBC_SHA) )
		{
			cipherKeySize = 16;
			cipher = new AES();
			blockSize = cipher.getBlockSize();
		}
		if( suite == CipherSuite.PSK_3DES_EDE_CBC_SHA )
		{
			cipherKeySize = 24;
			cipher = new DES3_EDE();
			blockSize = cipher.getBlockSize();
		}
		
		this.useExplicitIV = (session.protocolVersion > Protocol.TLSv1_0);

		// HMAC
		if( (suite == CipherSuite.PSK_AES_128_CBC_SHA256) || (suite == CipherSuite.PSK_NULL_SHA256) )
			hmac = new HMAC( new SHA256() );
		else
			hmac = new HMAC( new SHA1() );

		this.hmacSize = session.isTruncateHMac ? Math.min( hmac.getSize(), 10 ) : hmac.getSize();
		session.cryptLimit += hmacSize;
		session.log.writeln( COLOR_CRYPT, "       HMAC size :  " + hmacSize );

		int keyBlockSize = hmac.getSize() * 2 + cipherKeySize * 2;

		// From TLS 1.1 onwards, block ciphers don't need IVs from the key_block
		if( !useExplicitIV && (cipher != null) )
		{
			keyBlockSize += blockSize * 2;
		}

		Binary keyBlock = calcKeyBlock( keyBlockSize );
		session.log.writeln( COLOR_CRYPT, "       Key Block :  " + keyBlock.Hex() );

		int offset = 0;

		// Set HMAC Key
		hmac.setKey( keyBlock.slice( isServerKeys ? (offset + hmac.getSize()) : offset,  hmac.getSize() ) );
		offset += hmac.getSize() * 2;

		if( cipher != null )
		{
			session.cryptLimit += 256; // For padding

			// Set CIPHER Key
			cipher.setKey( keyBlock.slice( isServerKeys ? (offset + cipherKeySize) : offset, cipherKeySize ) );
			offset += cipherKeySize * 2;

			// Set IV
			session.log.writeln( COLOR_CRYPT, "      expicit IV :  " + useExplicitIV );
			if( useExplicitIV )
			{
				iv.assign( Bin( blockSize ) );
				session.cryptLimit += blockSize;
			}
			else
			{
				iv.assign( keyBlock, isServerKeys ? (offset + blockSize) : offset, blockSize );
				offset += blockSize * 2;
			}
			session.log.writeln( COLOR_CRYPT, "              IV :  " + iv.Hex() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static TlsPSKCrypt createEncoder( TlsPSKSession session, boolean isServerKeys )
	{
		session.log.writeln( COLOR_CRYPT, "    ENCODER : " );
		TlsPSKCrypt inst = new TlsPSKCrypt( session, isServerKeys );
		if( inst.cipher != null )
			inst.cipher.encryptFirst( Bin(), Bin(), CryptoMode.CBC, AlignMode.NONE, inst.iv );
		return inst;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static TlsPSKCrypt createDecoder( TlsPSKSession session, boolean isServerKeys )
	{
		session.log.writeln( COLOR_CRYPT, "    DECODER : " );
		TlsPSKCrypt inst = new TlsPSKCrypt( session, isServerKeys );
		if( inst.cipher != null )
			inst.cipher.decryptFirst( Bin(), Bin(), CryptoMode.CBC, AlignMode.NONE, inst.iv );
		return inst;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary calcMasterSecret( Binary psk )
	{
		Binary preMasterSecret = new Binary();
		preMasterSecret.addU16( psk.size() );
		preMasterSecret.add( new Binary( psk.size(), 0 ) ); // Other secret
		preMasterSecret.addU16( psk.size() );
		preMasterSecret.add( psk );

		return PRF( preMasterSecret, "master secret", Bin( session.clientRandom ).add( session.serverRandom ), 48 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary calcKeyBlock( int length )
	{
		return PRF( masterSecret, "key expansion", Bin( session.serverRandom ).add( session.clientRandom ), length );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected Binary calcVerifyData( boolean isFromServer )
	{
		String asciiLabel = isFromServer ? "server finished" : "client finished";

		Binary hash;
		if( session.protocolVersion == Protocol.TLSv1_2 )
			hash = new SHA256().calc( session.handshakeMessages );
		else
			hash = Bin( new MD5().calc( session.handshakeMessages ), new SHA1().calc( session.handshakeMessages ) ) ;

		session.log.writeln( COLOR_CRYPT, "  Handshake Hash :  " + hash.Hex() );

		return PRF( masterSecret, asciiLabel, hash, 12 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return padded data (same array)
	 */
	private Binary pad( Binary data )
	{
		int padLen = blockSize - (data.size() % blockSize);
		int padByte = padLen - 1;
		data.add( Bin( padLen, padByte ) );
		return data;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected Binary calcHMac( int recordType, Binary msg )
	{
		Binary b = new Binary().reserve( msg.size() + 13 );

		b.addLong( seqNo++ );
		b.add( recordType );
		b.addU16( session.protocolVersion );
		b.addU16( msg.size() );
		b.add( msg );

		return hmac.calc( b ).first( hmacSize );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected Binary encode( int contentType, final Binary plain )
	{
		Binary buf = Bin().reserve( plain.size() + blockSize + hmacSize );

		if( (cipher != null) && useExplicitIV )
			buf.add( Bin().randomSecure( blockSize ) );

		buf.add( plain );

		if( session.isEncryptThenMAC )
		{
			cipher.encryptNext( pad( buf ), buf );
			buf.add( calcHMac( contentType, buf ) );
		}
		else
		{
			buf.add( calcHMac( contentType, plain ) );
			if( cipher != null )
				cipher.encryptNext( pad( buf ), buf );
		}

		return buf;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected Binary decode( int recordType, final Binary crypt )
	{
		if( session.isEncryptThenMAC )
		{
			int minLen = blockSize + hmacSize + (useExplicitIV ? blockSize : 0);
			MUST( crypt.size() >= minLen, Alert.DECODE_ERROR );

			Binary encrypted = crypt.first( crypt.size() - hmacSize );
			Binary expectedMac = calcHMac( recordType, encrypted );
			MUST( crypt.last( hmacSize ).equals( expectedMac ), Alert.BAD_RECORD_MAC );

			MUST( encrypted.size() % blockSize == 0, Alert.BAD_RECORD_MAC );
			cipher.decryptNext( encrypted, encrypted );
			int padLen = checkPadding( encrypted, 0 );
			int ivLen = useExplicitIV ? blockSize : 0;
			return encrypted.slice( ivLen, encrypted.size() - padLen - ivLen );
		}
		else
		{
			int padLen = 0;
			int ivLen = 0;
			if( cipher != null )
			{
				MUST( crypt.size() % blockSize == 0, Alert.BAD_RECORD_MAC );
				cipher.decryptNext( crypt, crypt );
				padLen = checkPadding( crypt, 0 );
				ivLen = useExplicitIV ? blockSize : 0;
			}
			Binary plain = crypt.slice( ivLen, crypt.size() - padLen - ivLen - hmacSize );
			Binary mac = crypt.slice( crypt.size() - padLen - hmacSize, hmacSize );
			Binary expectedMac = calcHMac( recordType, plain );
			MUST( mac.equals( expectedMac ), Alert.BAD_RECORD_MAC );
			return plain;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private int checkPadding( Binary data, int macSize )
	{
		int len = data.size();
		int lastByte = data.get( data.size() - 1 );
		int padLen = lastByte + 1;

		int padLimit = Math.min( 256, len - macSize );

		if( padLen > padLimit )
			throw new Ex( Alert.BAD_RECORD_MAC );

		for( int i = len - padLen; i < len; ++i )
		{
			if( data.get( i ) != lastByte )
				throw new Ex( Alert.BAD_RECORD_MAC );
		}

		return padLen;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary PRF( final Binary data, String label, Binary seed, int length )
	{
		Binary labelSeed = Bin().fromUTF8( label ).add( seed );

		if( session.protocolVersion == Protocol.TLSv1_2 )
		{	// for TLS 1.2
			HMAC hmac = new HMAC( new SHA256() ).setKey( data );
			return HMAC_hash( hmac, labelSeed, length );
		}
		else
		{	// for TLS 1.0 and TLS 1.1
			int s_half = (data.size() + 1) / 2;
			HMAC hmac1 = new HMAC( new MD5() ).setKey( data.first( s_half ) );
			Binary b1 = HMAC_hash( hmac1, labelSeed, length );
			HMAC hmac2 = new HMAC( new SHA1() ).setKey( data.last( s_half ) );
			Binary b2 = HMAC_hash( hmac2, labelSeed, length );
			return b1.xor( b2 );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	// RFC 5246, 5. HMAC and the Pseudorandom Function
	private static Binary HMAC_hash( HMAC hmac, Binary seed, int length )
	{
		int macSize = hmac.getSize();
		Binary result = Bin().reserve( length );
		Binary Ai = seed; //  A(0) = seed 
		for( int offset = 0; offset < length; offset += macSize )
		{
			Ai = hmac.calc( Ai ); //  A(i) = HMAC_hash(secret, A(i-1))
			Binary resPart = hmac.calc( Bin( Ai, seed ) );  // HMAC_hash(secret, A(i) + seed)
			result.add( resPart, 0, Math.min( macSize, length - offset ) );
		}
		return result;
	}
}
