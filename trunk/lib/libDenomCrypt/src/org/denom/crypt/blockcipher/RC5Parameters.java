package org.denom.crypt.blockcipher;

import static org.denom.Ex.MUST;

public class RC5Parameters implements CipherParameters
{
	private byte[] key;
	private int rounds;

	public RC5Parameters( byte[] key, int rounds )
	{
		MUST( key.length <= 255, "RC5 key length can be no greater than 255" );

		this.key = new byte[ key.length ];
		this.rounds = rounds;

		System.arraycopy( key, 0, this.key, 0, key.length );
	}

	public byte[] getKey()
	{
		return key;
	}

	public int getRounds()
	{
		return rounds;
	}
}
