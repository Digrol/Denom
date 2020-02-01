// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import java.util.Arrays;
import org.denom.Binary;

/**
 * Cryptographic hash function GOST R 34.11-2012 (256 bit).
 * Differences from 512 version: initial filler and truncated hash.
 */
public final class GOST3411_2012_256 extends GOST3411_2012_512
{
	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String name()
	{
		return "GOST3411-2012-256";
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int size()
	{
		return 32;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary getHash()
	{
		return super.getHash().last( 32 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void reset()
	{
		super.reset();
		Arrays.fill( state, (byte)1 );
	}

}
