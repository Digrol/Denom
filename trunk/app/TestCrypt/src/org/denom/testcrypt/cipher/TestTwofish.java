package org.denom.testcrypt.cipher;

import org.denom.crypt.blockcipher.*;
import static org.denom.testcrypt.cipher.CheckCipher.*;

class TestTwofish
{
	TestTwofish()
	{
		Twofish cipher = new Twofish();
		String input = "000102030405060708090A0B0C0D0E0F";

		checkCipher( cipher, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", input, "8ef0272c42db838bcf7b07af0ec30f38" );
		checkCipher( cipher, "000102030405060708090a0b0c0d0e0f1011121314151617", input, "95accc625366547617f8be4373d10cd7" );
		checkCipher( cipher, "000102030405060708090a0b0c0d0e0f", input, "9fb63337151be9c71306d159ea7afaa4");

		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	public static void main( String[] args )
	{
		new TestTwofish();
	}
}
