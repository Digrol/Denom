package org.denom.testcrypt.cipher;

import org.denom.crypt.blockcipher.CAST5;
import static org.denom.testcrypt.cipher.CheckCipher.*;

/**
 * http://www.ietf.org/rfc/rfc2144.txt
 */
class TestCAST5
{
	TestCAST5()
	{
		CAST5 cipher = new CAST5();
		checkCipher( cipher, "0123456712345678234567893456789A", "0123456789ABCDEF", "238B4FE5847E44B2" );
		checkCipher( cipher, "01234567123456782345", "0123456789ABCDEF", "EB6A711A2C02271B" );
		checkCipher( cipher, "0123456712", "0123456789ABCDEF", "7Ac816d16E9B302E" );

		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	public static void main( String[] args )
	{
		new TestCAST5();
	}
}
