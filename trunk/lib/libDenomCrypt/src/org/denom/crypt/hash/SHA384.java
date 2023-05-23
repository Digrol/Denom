// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import org.denom.Binary;

/**
 * Cryptographic hash function SHA-384.
 * Differences from SHA-512: initial constants and truncated hash.
 */
public class SHA384 extends SHA512
{
	public final static int HASH_SIZE = 48;

	// -----------------------------------------------------------------------------------------------------------------
	public SHA384()
	{
		super( 0 );
		reset();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String name()
	{
		return "SHA-384";
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int size()
	{
		return HASH_SIZE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SHA384 clone()
	{
		return new SHA384();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SHA384 cloneState()
	{
		return (SHA384)super.cloneState();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void reset()
	{
		super.reset();
		H[0] = 0xcbbb9d5dc1059ed8L;
		H[1] = 0x629a292a367cd507L;
		H[2] = 0x9159015a3070dd17L;
		H[3] = 0x152fecd8f70e5939L;
		H[4] = 0x67332667ffc00b31L;
		H[5] = 0x8eb44a8768581511L;
		H[6] = 0xdb0c2e0d64f98fa7L;
		H[7] = 0x47b5481dbefa4fa4L;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary getHash()
	{
		return super.getHash().first( HASH_SIZE );
	}

}
