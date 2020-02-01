package org.denom.crypt.blockcipher;

import static org.denom.Ex.MUST;

/**
 * A parent class for block cipher modes that do not require block aligned data to be processed, but
 * can function in a streaming mode.
 */
public abstract class StreamBlockCipher implements BlockCipher, StreamCipher
{
	public final BlockCipher cipher;

	protected StreamBlockCipher( BlockCipher cipher )
	{
		this.cipher = cipher;
	}

	public BlockCipher getUnderlyingCipher()
	{
		return cipher;
	}

	public final byte returnByte( byte in )
	{
		return calculateByte( in );
	}

	public int processBytes( byte[] in, int inOff, int len, byte[] out, int outOff )
	{
		MUST( (inOff + len) <= in.length );
		MUST( (outOff + len) <= out.length );

		int inStart = inOff;
		int inEnd = inOff + len;
		int outStart = outOff;

		while( inStart < inEnd )
		{
			out[ outStart++ ] = calculateByte( in[ inStart++ ] );
		}

		return len;
	}

	protected abstract byte calculateByte( byte b );
}