// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.testcrypt;

import org.denom.*;
import org.denom.crypt.hash.*;

class Use_HMAC
{
	public static void main( String[] args )
	{
		Binary key = new Binary().fromUTF8( "key" );
		Binary data = new Binary().fromUTF8( "data" );
		HMAC hmac = new HMAC( new SHA1(), key );
		Ex.MUST( hmac.calc( data ).equals( "104152c5bfdca07bc633eebd46199f0255c9f49d" ) );
		System.out.println( "OK" );
	}
}
