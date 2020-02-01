package org.denom.crypt.blockcipher;

import static org.denom.Ex.MUST;

/**
 * Daniel J. Bernstein's ChaCha stream cipher.
 */
public class ChaCha7539 extends Salsa20
{
	public ChaCha7539()
	{
		super();
	}

	public String getAlgorithmName()
	{
		return "ChaCha7539-" + rounds;
	}

	protected int getNonceSize()
	{
		return 12;
	}

	protected void advanceCounter( long diff )
	{
		int hi = (int)(diff >>> 32);
		int lo = (int)diff;

		MUST( hi == 0, "attempt to increase counter past 2^32." );

		int oldState = engineState[ 12 ];

		engineState[ 12 ] += lo;

		if( oldState != 0 && engineState[ 12 ] < oldState )
		{
			throw new IllegalStateException( "attempt to increase counter past 2^32." );
		}
	}

	protected void advanceCounter()
	{
		MUST( ++engineState[ 12 ] != 0, "attempt to increase counter past 2^32." );
	}

	protected void retreatCounter( long diff )
	{
		int hi = (int)(diff >>> 32);
		int lo = (int)diff;

		if( hi != 0 )
		{
			throw new IllegalStateException( "attempt to reduce counter past zero." );
		}

		if( (engineState[ 12 ] & 0xffffffffL) >= (lo & 0xffffffffL) )
		{
			engineState[ 12 ] -= lo;
		}
		else
		{
			throw new IllegalStateException( "attempt to reduce counter past zero." );
		}
	}

	protected void retreatCounter()
	{
		if( engineState[ 12 ] == 0 )
		{
			throw new IllegalStateException( "attempt to reduce counter past zero." );
		}

		--engineState[ 12 ];
	}

	protected long getCounter()
	{
		return engineState[ 12 ] & 0xffffffffL;
	}

	protected void resetCounter()
	{
		engineState[ 12 ] = 0;
	}

	protected void setKey( byte[] keyBytes, byte[] ivBytes )
	{
		if( keyBytes != null )
		{
			if( keyBytes.length != 32 )
			{
				throw new IllegalArgumentException( getAlgorithmName() + " requires 256 bit key" );
			}

			packTauOrSigma( keyBytes.length, engineState, 0 );

			// Key
			Static.littleEndianToInt( keyBytes, 0, engineState, 4, 8 );
		}

		// IV
		Static.littleEndianToInt( ivBytes, 0, engineState, 13, 3 );
	}

	protected void generateKeyStream( byte[] output )
	{
		ChaCha.chachaCore( rounds, engineState, x );
		Static.intToLittleEndian( x, output, 0 );
	}
}
