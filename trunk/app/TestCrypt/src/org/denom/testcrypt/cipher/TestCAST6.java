package org.denom.testcrypt.cipher;

import org.denom.crypt.blockcipher.*;
import static org.denom.testcrypt.cipher.CheckCipher.*;

/**
 * http://www.ietf.org/rfc/rfc2612.txt
 */
class TestCAST6
{
	TestCAST6()
	{
		CAST6 cipher = new CAST6();
		String data = "00000000000000000000000000000000";
		checkCipher( cipher, "2342bb9efa38542c0af75647f29f615d", data, "c842a08972b43d20836c91d1b7530f6b" );
		checkCipher( cipher, "2342bb9efa38542cbed0ac83940ac298bac77a7717942863", data, "1b386c0210dcadcbdd0e41aa08a7a7e8" );
		checkCipher( cipher, "2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604", data, "4f6a2038286897b9c9870136553317fa" );

		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	public static void main( String[] args )
	{
		new TestCAST6();
	}
}
