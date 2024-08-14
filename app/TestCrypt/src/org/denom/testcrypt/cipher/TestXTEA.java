package org.denom.testcrypt.cipher;

import org.denom.crypt.blockcipher.*;
import static org.denom.testcrypt.cipher.CheckCipher.*;

/**
 * TEA tester - based on C implementation results from http://www.simonshepherd.supanet.com/tea.htm
 */
class TestXTEA
{
	TestXTEA()
	{
		XTEA cipher = new XTEA();
		checkCipher( cipher, "00000000000000000000000000000000", "0000000000000000", "dee9d4d8f7131ed9" );
		checkCipher( cipher, "00000000000000000000000000000000", "0102030405060708", "065c1b8975c6a816" );
		checkCipher( cipher, "0123456712345678234567893456789A", "0000000000000000", "1ff9a0261ac64264" );
		checkCipher( cipher, "0123456712345678234567893456789A", "0102030405060708", "8c67155b2ef91ead" );

		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	public static void main( String[] args )
	{
		new TestXTEA();
	}
}
