package org.denom.testcrypt.cipher;

import org.denom.Binary;
import org.denom.crypt.blockcipher.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

final class CheckCipher
{
	// -----------------------------------------------------------------------------------------------------------------
	static byte[] HexDecode( String data )
	{
		return new Binary( data ).getBytes();
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void checkCipher( BlockCipher aCipher, String keyHex, String dataHex, String cryptHex )
	{
		BufferedBlockCipher cipher = new BufferedBlockCipher( aCipher );
		KeyParameter params = new KeyParameter( Bin(keyHex) );
		
		Binary crypt = cipher.encrypt( params, Bin(dataHex) );
		MUST( crypt.equals( cryptHex ) );
		MUST( cipher.decrypt( params, crypt ).equals( dataHex ) );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	static void checkCipher( BlockCipher cipherEngine, String keyHex, String IV, String dataHex, String cryptHex )
	{
		BufferedBlockCipher cipher = new BufferedBlockCipher( cipherEngine );
		ParametersWithIV params = new ParametersWithIV( new KeyParameter( Bin(keyHex) ), Bin(IV).getBytes() );

		Binary crypt = cipher.encrypt( params, Bin(dataHex) );
		MUST( crypt.equals( cryptHex ) );
		MUST( cipher.decrypt( params, crypt ).equals( dataHex ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void checkMonteCarlo( BlockCipher aCipher, int iterations,
			String keyHex, String dataHex, String cryptHex )
	{
		BufferedBlockCipher cipher = new BufferedBlockCipher( aCipher );
		KeyParameter params = new KeyParameter( Bin(keyHex) );

		Binary crypt = Bin( dataHex );

		cipher.init( true, params );
		for( int i = 0; i < iterations; i++ )
		{
			int len1 = cipher.processBytes( crypt.getDataRef(), 0, crypt.size(), crypt.getDataRef(), 0 );
			cipher.doFinal( crypt.getDataRef(), len1 );
		}
		MUST( crypt.equals( cryptHex ) );

		cipher.init( false, params );
		for( int i = 0; i != iterations; i++ )
		{
			int len1 = cipher.processBytes( crypt.getDataRef(), 0, crypt.size(), crypt.getDataRef(), 0 );
			cipher.doFinal( crypt.getDataRef(), len1 );
		}

		MUST( Bin( crypt ).equals( dataHex ) );
	}
}
