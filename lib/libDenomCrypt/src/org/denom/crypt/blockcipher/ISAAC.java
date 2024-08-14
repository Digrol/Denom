package org.denom.crypt.blockcipher;

import static org.denom.Ex.MUST;

/**
 * Bob Jenkin's ISAAC (Indirection Shift Accumulate Add and Count).
 * http://www.burtleburtle.net/bob/rand/isaacafa.html
 */
public class ISAAC implements StreamCipher
{
	// Constants
	private final int sizeL = 8, stateArraySize = sizeL << 5; // 256

	// Cipher's internal state
	private int[] engineState = null; // mm
	private int[] results = null; // randrsl
	private int a = 0, b = 0, c = 0;

	// Engine state
	private int index = 0;
	private byte[] keyStream = new byte[ stateArraySize << 2 ]; // results expanded into bytes
	private byte[] workingKey = null;
	private boolean initialised = false;

	/**
	 * initialise an ISAAC cipher.
	 *
	 * @param forEncryption whether or not we are for encryption.
	 * @param params the parameters required to set up the cipher.
	 * @exception IllegalArgumentException if the params argument is inappropriate.
	 */
	public void init( boolean forEncryption, CipherParameters params )
	{
		MUST( params instanceof KeyParameter );
		KeyParameter p = (KeyParameter)params;
		setKey( p.getKey() );
	}

	public byte returnByte( byte in )
	{
		if( index == 0 )
		{
			isaac();
			keyStream = Static.intToBigEndian( results );
		}
		byte out = (byte)(keyStream[ index ] ^ in);
		index = (index + 1) & 1023;

		return out;
	}

	public int processBytes( byte[] in, int inOff, int len, byte[] out, int outOff )
	{
		MUST( initialised );
		MUST( (inOff + len) <= in.length );
		MUST( (outOff + len) <= out.length );

		for( int i = 0; i < len; i++ )
		{
			if( index == 0 )
			{
				isaac();
				keyStream = Static.intToBigEndian( results );
			}
			out[ i + outOff ] = (byte)(keyStream[ index ] ^ in[ i + inOff ]);
			index = (index + 1) & 1023;
		}

		return len;
	}

	public String getAlgorithmName()
	{
		return "ISAAC";
	}

	public void reset()
	{
		setKey( workingKey );
	}

	// Private implementation
	private void setKey( byte[] keyBytes )
	{
		workingKey = keyBytes;

		if( engineState == null )
		{
			engineState = new int[ stateArraySize ];
		}

		if( results == null )
		{
			results = new int[ stateArraySize ];
		}

		int i, j, k;

		// Reset state
		for( i = 0; i < stateArraySize; i++ )
		{
			engineState[ i ] = results[ i ] = 0;
		}
		a = b = c = 0;

		// Reset index counter for output
		index = 0;

		// Convert the key bytes to ints and put them into results[] for initialization
		byte[] t = new byte[ keyBytes.length + (keyBytes.length & 3) ];
		System.arraycopy( keyBytes, 0, t, 0, keyBytes.length );
		for( i = 0; i < t.length; i += 4 )
		{
			results[ i >>> 2 ] = Static.littleEndianToInt( t, i );
		}

		// It has begun?
		int[] abcdefgh = new int[ sizeL ];

		for( i = 0; i < sizeL; i++ )
		{
			abcdefgh[ i ] = 0x9e3779b9; // Phi (golden ratio)
		}

		for( i = 0; i < 4; i++ )
		{
			mix( abcdefgh );
		}

		for( i = 0; i < 2; i++ )
		{
			for( j = 0; j < stateArraySize; j += sizeL )
			{
				for( k = 0; k < sizeL; k++ )
				{
					abcdefgh[ k ] += (i < 1) ? results[ j + k ] : engineState[ j + k ];
				}

				mix( abcdefgh );

				for( k = 0; k < sizeL; k++ )
				{
					engineState[ j + k ] = abcdefgh[ k ];
				}
			}
		}

		isaac();

		initialised = true;
	}

	private void isaac()
	{
		int i, x, y;

		b += ++c;
		for( i = 0; i < stateArraySize; i++ )
		{
			x = engineState[ i ];
			switch( i & 3 )
			{
				case 0:
					a ^= (a << 13);
					break;
				case 1:
					a ^= (a >>> 6);
					break;
				case 2:
					a ^= (a << 2);
					break;
				case 3:
					a ^= (a >>> 16);
					break;
			}
			a += engineState[ (i + 128) & 0xFF ];
			engineState[ i ] = y = engineState[ (x >>> 2) & 0xFF ] + a + b;
			results[ i ] = b = engineState[ (y >>> 10) & 0xFF ] + x;
		}
	}

	private void mix(int[] x)
	{
		x[0]^=x[1]<< 11; x[3]+=x[0]; x[1]+=x[2];
		x[1]^=x[2]>>> 2; x[4]+=x[1]; x[2]+=x[3];
		x[2]^=x[3]<<  8; x[5]+=x[2]; x[3]+=x[4];
		x[3]^=x[4]>>>16; x[6]+=x[3]; x[4]+=x[5];
		x[4]^=x[5]<< 10; x[7]+=x[4]; x[5]+=x[6];
		x[5]^=x[6]>>> 4; x[0]+=x[5]; x[6]+=x[7];
		x[6]^=x[7]<<  8; x[1]+=x[6]; x[7]+=x[0];
		x[7]^=x[0]>>> 9; x[2]+=x[7]; x[0]+=x[1];
	}
}
