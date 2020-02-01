// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.format;

import org.denom.Binary;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Serialize object's data (state or something else) as Binary array and restore data from Binary.
 * See 'Denom Structured Data Standard'.
 */
public interface IBinable
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Append serialized data to Binary array.
	 */
	void toBin( Binary res );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Serialize to Binary array.
	 */
	default Binary toBin()
	{
		Binary b = new Binary();
		toBin( b );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Restore data from Binary array.
	 */
	default IBinable fromBin( final Binary bin )
	{
		return fromBin( bin, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Restore data from Binary array.
	 * @param offset - start from this offset.
	 */
	IBinable fromBin( final Binary bin, int offset );
}
