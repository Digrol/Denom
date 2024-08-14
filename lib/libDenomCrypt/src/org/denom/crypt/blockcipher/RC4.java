package org.denom.crypt.blockcipher;

import static org.denom.Ex.MUST;

public class RC4 implements StreamCipher
{
	private final static int STATE_LENGTH = 256;

	/*
	 * variables to hold the state of the RC4 engine during encryption and decryption
	 */

	private byte[] engineState = null;
	private int x = 0;
	private int y = 0;
	private byte[] workingKey = null;

	/**
	 * initialise a RC4 cipher.
	 *
	 * @param forEncryption whether or not we are for encryption.
	 * @param params the parameters required to set up the cipher.
	 * @exception IllegalArgumentException if the params argument is inappropriate.
	 */
	public void init( boolean forEncryption, CipherParameters params )
	{
		MUST( params instanceof KeyParameter );
		workingKey = ((KeyParameter)params).getKey();
		setKey( workingKey );
	}

	public String getAlgorithmName()
	{
		return "RC4";
	}

	public byte returnByte( byte in )
	{
		x = (x + 1) & 0xff;
		y = (engineState[ x ] + y) & 0xff;

		// swap
		byte tmp = engineState[ x ];
		engineState[ x ] = engineState[ y ];
		engineState[ y ] = tmp;

		// xor
		return (byte)(in ^ engineState[ (engineState[ x ] + engineState[ y ]) & 0xff ]);
	}

	public int processBytes( byte[] in, int inOff, int len, byte[] out, int outOff )
	{
		MUST( (inOff + len) <= in.length );
		MUST( (outOff + len) <= out.length );

		for( int i = 0; i < len; i++ )
		{
			x = (x + 1) & 0xff;
			y = (engineState[ x ] + y) & 0xff;

			// swap
			byte tmp = engineState[ x ];
			engineState[ x ] = engineState[ y ];
			engineState[ y ] = tmp;

			// xor
			out[ i + outOff ] = (byte)(in[ i + inOff ] ^ engineState[ (engineState[ x ] + engineState[ y ]) & 0xff ]);
		}

		return len;
	}

	public void reset()
	{
		setKey( workingKey );
	}

	// Private implementation

	private void setKey( byte[] keyBytes )
	{
		workingKey = keyBytes;

		// System.out.println("the key length is ; "+ workingKey.length);

		x = 0;
		y = 0;

		if( engineState == null )
		{
			engineState = new byte[ STATE_LENGTH ];
		}

		// reset the state of the engine
		for( int i = 0; i < STATE_LENGTH; i++ )
		{
			engineState[ i ] = (byte)i;
		}

		int i1 = 0;
		int i2 = 0;

		for( int i = 0; i < STATE_LENGTH; i++ )
		{
			i2 = ((keyBytes[ i1 ] & 0xff) + engineState[ i ] + i2) & 0xff;
			// do the byte-swap inline
			byte tmp = engineState[ i ];
			engineState[ i ] = engineState[ i2 ];
			engineState[ i2 ] = tmp;
			i1 = (i1 + 1) % keyBytes.length;
		}
	}
}
