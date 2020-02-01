package org.denom.testcrypt.cipher;

import org.denom.crypt.blockcipher.*;
import static org.denom.testcrypt.cipher.CheckCipher.*;

class TestIDEA
{
	TestIDEA()
	{
		checkCipher( new IDEA(), "00112233445566778899AABBCCDDEEFF",
			"000102030405060708090a0b0c0d0e0f", "ed732271a7b39f475b4b2b6719f194bf");
		checkCipher( new IDEA(), "00112233445566778899AABBCCDDEEFF",
			"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "b8bc6ed5c899265d2bcfad1fc6d4287d" );

		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	public static void main( String[] args )
	{
		new TestIDEA();
	}
}
