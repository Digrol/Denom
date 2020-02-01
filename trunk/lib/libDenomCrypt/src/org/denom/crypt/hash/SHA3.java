// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import static org.denom.Ex.MUST;

/**
 * Cryptographic hash function SHA3.
 * Differences from Keccak: pad bits.
 */
public class SHA3 extends Keccak
{
	// -----------------------------------------------------------------------------------------------------------------
	public SHA3( int bitLen )
	{
		super( bitLen );
		MUST( (bitLen == 224) || (bitLen == 256) || (bitLen == 384) || (bitLen == 512), "Wrong hashSize for SHA-3" );
		padBits = 0x06;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public String name()
	{
		return "SHA3-" + hashSizeBits;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SHA3 clone()
	{
		return new SHA3( this.hashSizeBits );
	}
}
