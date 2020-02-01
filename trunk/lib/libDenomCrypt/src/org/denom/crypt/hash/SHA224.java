// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import org.denom.Binary;

/**
 * Cryptographic hash function SHA-224.
 * Differences from SHA-256: initial constants and truncated hash.
 */
public class SHA224 extends SHA256
{
	public final static int HASH_SIZE = 28;

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String name()
	{
		return "SHA-224";
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int size()
	{
		return HASH_SIZE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SHA224 clone()
	{
		return new SHA224();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void reset()
	{
		super.reset();
		H[0] = 0xc1059ed8;
		H[1] = 0x367cd507;
		H[2] = 0x3070dd17;
		H[3] = 0xf70e5939;
		H[4] = 0xffc00b31;
		H[5] = 0x68581511;
		H[6] = 0x64f98fa7;
		H[7] = 0xbefa4fa4;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary getHash()
	{
		return super.getHash().first( HASH_SIZE );
	}
}
