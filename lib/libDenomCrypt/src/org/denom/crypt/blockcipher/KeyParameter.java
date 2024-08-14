package org.denom.crypt.blockcipher;

import org.denom.Binary;

public class KeyParameter implements CipherParameters
{
	private byte[] key;

	public KeyParameter( byte[] key )
	{
		this.key = key.clone();
	}

	public KeyParameter( Binary aKey )
	{
		this.key = aKey.getBytes();
	}

	public byte[] getKey()
	{
		return key;
	}
}
