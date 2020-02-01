package org.denom.testcrypt.cipher;

import org.denom.crypt.blockcipher.*;
import static org.denom.testcrypt.cipher.CheckCipher.*;

/**
 * http://www.ietf.org/rfc/rfc4009.txt
 */
public class TestSEED
{
	TestSEED()
	{
		SEED cipher = new SEED();
		checkCipher( cipher, "00000000000000000000000000000000",
			"000102030405060708090a0b0c0d0e0f", "5EBAC6E0054E166819AFF1CC6D346CDB" );

		checkCipher( cipher, "000102030405060708090a0b0c0d0e0f",
			"00000000000000000000000000000000", "c11f22f20140505084483597e4370f43" );

		checkCipher( cipher, "4706480851E61BE85D74BFB3FD956185",
			"83A2F8A288641FB9A4E9A5CC2F131C7D", "EE54D13EBCAE706D226BC3142CD40D4A" );

		checkCipher( cipher, "28DBC3BC49FFD87DCFA509B11D422BE7",
			"B41E6BE2EBA84A148E2EED84593C5EC7", "9B9B7BFCD1813CB95D0B3618F40F5122" );

		checkCipher( cipher, "0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E",
			"0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E", "8296F2F1B007AB9D533FDEE35A9AD850" );

		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	public static void main( String[] args )
	{
		new TestSEED();
	}
}
