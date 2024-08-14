// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.format;

import org.denom.Binary;
import static org.denom.Ex.MUST;

/**
 * Convert ASN.1 OID String to Binary and back.
 * Example: toStr( Bin("2A864886F70D0205")) -> "1.2.840.113549.2.5".
 */
public final class ASN1OID
{
	// -----------------------------------------------------------------------------------------------------------------
	// in REVERSE order
	private static void appendNum( Binary res, long num )
	{
		res.add( (int)num & 0x7F );
		num >>>= 7;
		while( num != 0 )
		{
			res.add( ((int)num & 0x7F) | 0x80 );
			num >>>= 7;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static Binary toBin( String oidStr )
	{
		Binary res = new Binary().reserve( 16 );

		String[] nums = oidStr.split( "\\." );
		MUST( nums.length >= 2, "Too short OID String" );

		// Processing nums in REVERSE order to simplify alg.
		for( int i = nums.length - 1; i > 1; --i )
		{
			long num = Long.parseLong( nums[ i ] );
			appendNum( res, num );
		}
		appendNum( res, Integer.parseInt( nums[0] ) * 40 + Integer.parseInt( nums[1] ) );

		return res.reverse();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static String toStr( Binary oid )
	{
		MUST( oid.size() > 1, "Too short OID" );

		StringBuilder s = new StringBuilder();
		long num = 0;
		boolean first = true;

		for( int i = 0; i < oid.size(); ++i )
		{
			int b = oid.get( i );

			num += (b & 0x7f);
			if( b > 0x7F )
			{
				num <<= 7;
				continue;
			}

			if( first )
			{
				int n1 = 0;
				while( (n1 < 2) && (num > 40) )
				{
					++n1;
					num -= 40;
				}
				s.append( n1 );
				first = false;
			}

			s.append( '.' );
			s.append( num );
			num = 0;
		}

		return s.toString();
	}

}