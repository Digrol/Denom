package org.denom.testcrypt.cipher;

import org.denom.crypt.blockcipher.*;
import static org.denom.testcrypt.cipher.CheckCipher.*;

/**
 * RC6 Test - test vectors from AES Submitted RSA Reference implementation.
 * ftp://ftp.funet.fi/pub/crypt/cryptography/symmetric/aes/rc6-unix-refc.tar
 */
public class TestRC6
{
	TestRC6()
	{
		RC6 cipher = new RC6();
		checkCipher( cipher, "00000000000000000000000000000000",
				"80000000000000000000000000000000", "f71f65e7b80c0c6966fee607984b5cdf");

		checkCipher( cipher, "000000000000000000000000000000008000000000000000",
				"00000000000000000000000000000000", "dd04c176440bbc6686c90aee775bd368");

		checkCipher( cipher, "000000000000000000000000000000000000001000000000",
				"00000000000000000000000000000000", "937fe02d20fcb72f0f57201012b88ba4");

		checkCipher( cipher, "00000001000000000000000000000000",
				"00000000000000000000000000000000", "8a380594d7396453771a1dfbe2914c8e");

		checkCipher( cipher, "1000000000000000000000000000000000000000000000000000000000000000",
				"00000000000000000000000000000000", "11395d4bfe4c8258979ee2bf2d24dff4");

		checkCipher( cipher, "0000000000000000000000000000000000080000000000000000000000000000",
				"00000000000000000000000000000000", "3d6f7e99f6512553bb983e8f75672b97");
	
		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	public static void main( String[] args )
	{
		new TestRC6();
	}
}
