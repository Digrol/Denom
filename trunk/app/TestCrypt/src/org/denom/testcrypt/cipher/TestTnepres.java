package org.denom.testcrypt.cipher;

import org.denom.crypt.blockcipher.*;
import static org.denom.testcrypt.cipher.CheckCipher.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.*;

/**
 * Test vectors based on Floppy 4 of the Serpent AES submission.
 */
class TestTnepres
{
	TestTnepres()
	{
		Tnepres cipher = new Tnepres();
		checkCipher( cipher, "0000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000", "8910494504181950f98dd998a82b6749" );

		checkCipher( cipher, "00000000000000000000000000000000",
			"80000000000000000000000000000000", "10b5ffb720b8cb9002a1142b0ba2e94a" );

		checkCipher( cipher, "00000000000000000000000000000000",
			"00000000008000000000000000000000", "4f057a42d8d5bd9746e434680ddcd5e5" );

		checkCipher( cipher, "00000000000000000000000000000000",
			"00000000000000000000400000000000", "99407bf8582ef12550886ef5b6f169b9" );

		checkCipher( cipher, "000000000000000000000000000000000000000000000000",
			"40000000000000000000000000000000", "d522a3b8d6d89d4d2a124fdd88f36896" );

		checkCipher( cipher, "000000000000000000000000000000000000000000000000",
			"00000000000200000000000000000000", "189b8ec3470085b3da97e82ca8964e32" );

		checkCipher( cipher, "000000000000000000000000000000000000000000000000",
			"00000000000000000000008000000000", "f77d868cf760b9143a89809510ccb099" );

		checkCipher( cipher, "0000000000000000000000000000000000000000000000000000000000000000",
			"08000000000000000000000000000000", "d43b7b981b829342fce0e3ec6f5f4c82" );

		checkCipher( cipher, "0000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000100000000000000", "0bf30e1a0c33ccf6d5293177886912a7" );

		checkCipher( cipher, "0000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000001", "6a7f3b805d2ddcba49b89770ade5e507" );

		checkCipher( cipher, "80000000000000000000000000000000",
			"00000000000000000000000000000000", "49afbfad9d5a34052cd8ffa5986bd2dd" );

		checkCipher( cipher, "000000000000000000000000004000000000000000000000",
			"00000000000000000000000000000000", "ba8829b1de058c4b48615d851fc74f17" );

		checkCipher( cipher, "0000000000000000000000000000000000000000000000000000000100000000",
			"00000000000000000000000000000000", "89f64377bf1e8a46c8247044e8056a98" );

		checkMonteCarlo( cipher, 10000, "47f5f881daab9b67b43bd1342e339c19",
			"7a4f7db38c52a8b711b778a38d203b6b", "003380e19f10065740394f48e2fe80b7" );

		checkMonteCarlo( cipher, 100, 
			"47f5f881daab9b67b43bd1342e339c19",
			"7a4f7db38c52a8b711b778a38d203b6b", "4db75303d815c2f7cc6ca935d1c5a046" );

		checkMonteCarlo( cipher, 10000,
			"31fba879ebc5e80df35e6fa33eaf92d6",
			"70a05e12f74589009692a337f53ff614", "afb5425426906db26b70bdf842ac5400" );

		checkMonteCarlo( cipher, 100,
			"31fba879ebc5e80df35e6fa33eaf92d6",
			"70a05e12f74589009692a337f53ff614", "fc53a50f4d3bc9836001893d2f41742d" );

		checkMonteCarlo( cipher, 10000,
			"bde6dd392307984695aee80e574f9977caae9aa78eda53e8",
			"9cc523d034a93740a0aa4e2054bb34d8", "1949d506ada7de1f1344986e8ea049b2");

		checkMonteCarlo( cipher, 100,
			"bde6dd392307984695aee80e574f9977caae9aa78eda53e8",
			"9cc523d034a93740a0aa4e2054bb34d8", "77117e6a9e80f40b2a36b7d755573c2d");

		checkMonteCarlo( cipher, 10000,
			"60f6f8ad4290699dc50921a1bbcca92da914e7d9cf01a9317c79c0af8f2487a1",
			"ee1a61106fae2d381d686cbf854bab65", "e57f45559027cb1f2ed9603d814e1c34" );

		checkMonteCarlo( cipher, 100,
			"60f6f8ad4290699dc50921a1bbcca92da914e7d9cf01a9317c79c0af8f2487a1",
			"ee1a61106fae2d381d686cbf854bab65", "dcd7f13ea0dcdfd0139d1a42e2ffb84b" );

		doCbcMonte( new byte[ 16 ], new byte[ 16 ], new byte[ 16 ], HexDecode( "9ea101ecebaa41c712bcb0d9bab3e2e4" ) );
		doCbcMonte( HexDecode( "9ea101ecebaa41c712bcb0d9bab3e2e4" ), HexDecode( "9ea101ecebaa41c712bcb0d9bab3e2e4" ), HexDecode( "b4813d8a66244188b9e92c75913fa2f4" ), HexDecode( "f86b2c265b9c75869f31e2c684c13e9f" ) );

		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	private void doCbcMonte( byte[] key, byte[] iv, byte[] pt, byte[] expected )
	{
		Tnepres c = new Tnepres();
		byte[] ct = new byte[ 16 ];
		System.arraycopy( iv, 0, ct, 0, 16 );

		for( int i = 0; i < 10000; i++ )
		{
			for( int k = 0; k != iv.length; k++ )
			{
				iv[ k ] ^= pt[ k ];
			}
			System.arraycopy( ct, 0, pt, 0, 16 );

			c.init( true, new KeyParameter( key ) );
			c.processBlock( iv, 0, ct, 0 );

			System.arraycopy( ct, 0, iv, 0, 16 );
		}

		MUST( Bin( expected ).equals( ct ) );
	}

	public static void main( String[] args )
	{
		new TestTnepres();
	}
}
