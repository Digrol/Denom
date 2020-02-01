package org.denom.testcrypt.cipher;

import org.denom.crypt.blockcipher.Blowfish;
import static org.denom.testcrypt.cipher.CheckCipher.*;

/**
 * http://www.counterpane.com/vectors.txt
 */
public class TestBlowfish
{
	TestBlowfish()
	{
		Blowfish cipher = new Blowfish();
		checkCipher( cipher, "0000000000000000", "0000000000000000", "4EF997456198DD78" );
		checkCipher( cipher, "FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A" );
		checkCipher( cipher, "3000000000000000", "1000000000000001", "7D856F9A613063F2" );
		checkCipher( cipher, "1111111111111111", "1111111111111111", "2466DD878B963C9D" );
		checkCipher( cipher, "0123456789ABCDEF", "1111111111111111", "61F9C3802281B096" );
		checkCipher( cipher, "FEDCBA9876543210", "0123456789ABCDEF", "0ACEAB0FC6A0A28D" );
		checkCipher( cipher, "7CA110454A1A6E57", "01A1D6D039776742", "59C68245EB05282B" );
		checkCipher( cipher, "0131D9619DC1376E", "5CD54CA83DEF57DA", "B1B8CC0B250F09A0" );

		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	public static void main( String[] args )
	{
		new TestBlowfish();
	}
}
