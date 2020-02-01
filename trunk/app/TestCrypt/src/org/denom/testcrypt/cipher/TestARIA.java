package org.denom.testcrypt.cipher;

import java.security.SecureRandom;
import org.denom.crypt.blockcipher.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;
import static org.denom.testcrypt.cipher.CheckCipher.*;

class TestARIA
{
	private static SecureRandom R = new SecureRandom();

	private static final String[][] TEST_VECTORS_RFC5794 = {
		{
			"128-Bit Key",
			"000102030405060708090a0b0c0d0e0f",
			"00112233445566778899aabbccddeeff",
			"d718fbd6ab644c739da95f3be6451778"
		},
		{
			"192-Bit Key",
			"000102030405060708090a0b0c0d0e0f1011121314151617",
			"00112233445566778899aabbccddeeff",
			"26449c1805dbe7aa25a468ce263a9e79"
		},
		{
			"256-Bit Key",
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"00112233445566778899aabbccddeeff",
			"f92bd7c79fb72e2f2b8f80c1972d24fc"
		}
	};

	TestARIA()
	{
		checkTestVectors_RFC5794();

		for( int i = 0; i < 100; ++i )
		{
			checkRandomRoundtrips();
		}

		new MyARIA().checkImplementation();
		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	private void checkRandomRoundtrips()
	{
		ARIA ce = new ARIA();
		ARIA cd = new ARIA();

		byte[] txt = new byte[ ce.getBlockSize() ];
		byte[] enc = new byte[ ce.getBlockSize() ];
		byte[] dec = new byte[ ce.getBlockSize() ];

		for( int keyLen = 16; keyLen <= 32; keyLen += 8 )
		{
			byte[] K = new byte[ keyLen ];

			R.nextBytes( K );

			KeyParameter key = new KeyParameter( K );
			ce.init( true, key );
			cd.init( false, key );

			R.nextBytes( txt );

			for( int i = 0; i < 100; ++i )
			{
				ce.processBlock( txt, 0, enc, 0 );
				cd.processBlock( enc, 0, dec, 0 );

				MUST( Bin(txt).equals( dec ) );

				System.arraycopy( enc, 0, txt, 0, enc.length );
			}
		}
	}

	private void checkTestVector_RFC5794( String[] tv )
	{
		BlockCipher c = new ARIA();
		int blockSize = c.getBlockSize();
		MUST( 16 == blockSize );

		KeyParameter key = new KeyParameter( HexDecode( tv[ 1 ] ) );
		byte[] plaintext = HexDecode( tv[ 2 ] );
		byte[] ciphertext = HexDecode( tv[ 3 ] );

		MUST( blockSize == plaintext.length );
		MUST( blockSize == ciphertext.length );

		c.init( true, key );
		byte[] actual = new byte[ blockSize ];
		int num = c.processBlock( plaintext, 0, actual, 0 );

		MUST( blockSize == num );
		MUST( Bin( ciphertext ).equals( actual ) );

		c.init( false, key );
		num = c.processBlock( ciphertext, 0, actual, 0 );

		MUST( blockSize == num );
		MUST( Bin( plaintext ).equals( actual ) );
	}

	private void checkTestVectors_RFC5794()
	{
		for( int i = 0; i < TEST_VECTORS_RFC5794.length; ++i )
		{
			checkTestVector_RFC5794( TEST_VECTORS_RFC5794[ i ] );
		}
	}

	private class MyARIA extends ARIA
	{
		public void checkImplementation()
		{
			checkInvolution();
			checkSBoxes();
		}

		private void checkInvolution()
		{
			byte[] x = new byte[ 16 ], y = new byte[ 16 ];

			for( int i = 0; i < 100; ++i )
			{
				R.nextBytes( x );
				System.arraycopy( x, 0, y, 0, 16 );
				A( y );
				A( y );
				MUST( Bin( x ).equals( y ) );
			}
		}

		private void checkSBoxes()
		{
			for( int i = 0; i < 256; ++i )
			{
				byte x = (byte)i;

				MUST( x == SB1( SB3( x ) ) );
				MUST( x == SB3( SB1( x ) ) );

				MUST( x == SB2( SB4( x ) ) );
				MUST( x == SB4( SB2( x ) ) );
			}
		}
	}

	public static void main( String[] args )
	{
		new TestARIA();
	}
}
