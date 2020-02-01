package org.denom.testcrypt.cipher;

import org.denom.crypt.blockcipher.*;
import org.denom.Binary;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * RC5 tester - vectors from ftp://ftp.nordu.net/rfc/rfc2040.txt
 * RFC 2040 "The RC5, RC5-CBC, RC5-CBC-Pad, and RC5-CTS Algorithms"
 */
public class TestRC5
{
	// -----------------------------------------------------------------------------------------------------------------
	void check( BlockCipher cipherEngine, String keyHex, int rounds, String IV, String dataHex, String cryptHex )
	{
		BufferedBlockCipher cipher = new BufferedBlockCipher( new CBCBlockCipher( cipherEngine ) );
		ParametersWithIV params =  new ParametersWithIV(
				new RC5Parameters( Bin(keyHex).getBytes(), rounds ), Bin(IV).getBytes() );

		Binary crypt = cipher.encrypt( params, Bin(dataHex) );
		MUST( crypt.equals( cryptHex ) );
		MUST( cipher.decrypt( params, crypt ).equals( dataHex ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	TestRC5()
	{
		RC5_32 cipher32 = new RC5_32();
		check( cipher32, "00", 0, "0000000000000000", "0000000000000000", "7a7bba4d79111d1e" );
		check( cipher32, "00", 0, "0000000000000000", "ffffffffffffffff", "797bba4d78111d1e" );
		check( cipher32, "00", 0, "0000000000000001", "0000000000000000", "7a7bba4d79111d1f" ); 
		check( cipher32, "00", 0, "0000000000000000", "0000000000000001", "7a7bba4d79111d1f" );
		check( cipher32, "00", 0, "0102030405060708", "1020304050607080", "8b9ded91ce7794a6" );
		check( cipher32, "11", 1, "0000000000000000", "0000000000000000", "2f759fe7ad86a378" );
		check( cipher32, "00", 2, "0000000000000000", "0000000000000000", "dca2694bf40e0788" );
		check( cipher32, "00000000", 2, "0000000000000000", "0000000000000000", "dca2694bf40e0788");
		check( cipher32, "00000000", 8, "0000000000000000", "0000000000000000", "dcfe098577eca5ff");
		check( cipher32, "00",  8, "0102030405060708", "1020304050607080", "9646fb77638f9ca8" );
		check( cipher32, "00", 12, "0102030405060708", "1020304050607080", "b2b3209db6594da4" );
		check( cipher32, "00", 16, "0102030405060708", "1020304050607080", "545f7f32a5fc3836" );
		check( cipher32, "01020304", 8, "0000000000000000", "ffffffffffffffff", "8285e7c1b5bc7402");
		check( cipher32, "01020304", 12, "0000000000000000", "ffffffffffffffff", "fc586f92f7080934");
		check( cipher32, "01020304", 16, "0000000000000000", "ffffffffffffffff", "cf270ef9717ff7c4");
		check( cipher32, "0102030405060708", 12, "0000000000000000", "ffffffffffffffff", "e493f1c1bb4d6e8c" );
		check( cipher32, "0102030405060708", 8, "0102030405060708", "1020304050607080", "5c4c041e0f217ac3");
		check( cipher32, "0102030405060708", 12, "0102030405060708", "1020304050607080", "921f12485373b4f7");
		check( cipher32, "0102030405060708", 16, "0102030405060708", "1020304050607080", "5ba0ca6bbe7f5fad" );
		check( cipher32, "01020304050607081020304050607080", 8, "0102030405060708", "1020304050607080", "c533771cd0110e63");
		check( cipher32, "01020304050607081020304050607080", 12, "0102030405060708", "1020304050607080", "294ddb46b3278d60");
		check( cipher32, "01020304050607081020304050607080", 16, "0102030405060708", "1020304050607080", "dad6bda9dfe8f7e8" );
		check( cipher32, "0102030405", 12, "0000000000000000", "ffffffffffffffff", "97e0787837ed317f" );
		check( cipher32, "0102030405", 8, "0000000000000000", "ffffffffffffffff", "7875dbf6738c6478" );
		check( cipher32, "0102030405", 8, "7875dbf6738c6478", "0808080808080808", "8f34c3c681c99695" );
		check( new RC5_64(), "00", 0, "00000000000000000000000000000000", "00000000000000000000000000000000", "9f09b98d3f6062d9d4d59973d00e0e63" );
		check( new RC5_64(), "00", 0, "00000000000000000000000000000000", "ffffffffffffffffffffffffffffffff", "9e09b98d3f6062d9d3d59973d00e0e63" );

		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	public static void main( String[] args )
	{
		new TestRC5();
	}
}
