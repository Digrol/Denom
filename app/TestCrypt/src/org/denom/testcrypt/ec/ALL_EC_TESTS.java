// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.testcrypt.ec;

import org.denom.log.*;
import org.denom.testcrypt.ec.rfc7748.*;

class ALL_EC_TESTS
{
//	private static ILog log = new LogConsole();
	private static ILog log = new LogColoredConsoleWindow();

	public static void main( String[] args )
	{
		new TestInterleave( log );
		new TestElGamal( log );

		new TestGOST3410( log );
		new TestSecp256r1( log );
		new TestSecp384r1( log );

		new TestVsJCE( log, 100 );
		new TestFpCurves( log, 100 );
		new TestF2mCurves( log, 100 );

		new TestX25519( log );
		new TestX448( log );
		new TestEd25519( log );
		new TestEd448( log );

		log.writeln( "All done" );
	}
}
