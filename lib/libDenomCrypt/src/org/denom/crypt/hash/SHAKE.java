// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import static org.denom.Ex.*;

/**
 * Cryptographic hash function SHAKE.
 * Differences from Keccak: pad bits.
 */
public class SHAKE extends Keccak
{
	// -----------------------------------------------------------------------------------------------------------------
	public SHAKE( int bitLen )
	{
		super( bitLen );
		MUST( (bitLen == 128) || (bitLen == 256), "Wrong hashSize for SHAKE" );
		padBits = 0x1F;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String name()
	{
		return "SHAKE" + hashSizeBits;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SHAKE clone()
	{
		return new SHAKE( this.hashSizeBits );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SHAKE cloneState()
	{
		return (SHAKE)super.cloneState();
	}

}
