// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.scp81;

import org.denom.*;
import org.denom.format.*;
import org.denom.smartcard.CApdu;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

public class ExpandedCApdu
{
	public Arr<Binary> capdus = new Arr<>();

	// -----------------------------------------------------------------------------------------------------------------
	public ExpandedCApdu() {}

	// -----------------------------------------------------------------------------------------------------------------
	public void add( Binary capdu )
	{
		capdus.add( capdu );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void add( String capduHex )
	{
		capdus.add( Bin(capduHex) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void add( CApdu capdu )
	{
		capdus.add( capdu.toBin() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary toBin()
	{
		Binary b = Bin( "AE80" );
		MUST( capdus.size() > 0, "ExpandedCApdu: no capdus" );
		for( Binary capdu : capdus )
			b.add( BerTLV.Tlv( 0x22, capdu ) );

		b.add( "00 00" );
		return b;
	}

}
