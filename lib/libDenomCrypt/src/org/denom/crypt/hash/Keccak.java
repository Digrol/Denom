// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import java.util.Arrays;
import org.denom.Binary;

import static java.lang.Long.rotateLeft;
import static org.denom.Ex.*;

/**
 * Cryptographic hash function Keccak.
 */
public class Keccak extends IHash
{
	protected int hashSizeBits;
	protected byte padBits = 0x01;

	protected long[] state = new long[ 25 ];

	// -----------------------------------------------------------------------------------------------------------------
	private static long[] CONSTANTS = new long[] {
		0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
		0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
		0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
		0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
		0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
		0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L };

	// -----------------------------------------------------------------------------------------------------------------
	public Keccak( int bitLen )
	{
		super( (1600 - (bitLen << 1)) >>> 3 );
		
		MUST( (bitLen == 128) || (bitLen == 224) || (bitLen == 256)
				|| (bitLen == 288) || (bitLen == 384) || (bitLen == 512),
			"Wrong hash size for Keccak" );

		this.hashSizeBits = bitLen;
		reset();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int size()
	{
		return hashSizeBits >>> 3;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String name()
	{
		return "Keccak-" + hashSizeBits;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Keccak clone()
	{
		return new Keccak( this.hashSizeBits );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Keccak cloneState()
	{
		Keccak cloned = (Keccak)super.cloneStateBase();
		MUST( cloned.hashSizeBits == this.hashSizeBits, "Wrong implementation of cloneState" );
		MUST( cloned.padBits == this.padBits, "Wrong implementation of cloneState" );

		cloned.state = Arrays.copyOf( this.state, this.state.length );
		return cloned;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void reset()
	{
		super.reset();
		Arrays.fill( this.state, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary getHash()
	{
		return getHash( hashSizeBits >>> 3 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param wantHashSize in bytes
	 */
	public Binary getHash( int wantHashSize )
	{
		finish();

		Binary hash = squeeze( wantHashSize );
		reset();
		return hash;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void finish()
	{
		int tailLen = tail.size();
		if( (tailLen + 1) == blockSize )
		{
			tail.add( padBits | 0x80 );
		}
		else
		{
			tail.resize( blockSize );
			tail.set( tailLen, padBits );
			tail.set( tail.size() - 1, 0x80 );
		}

		processBlock( tail, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected void processBlock( Binary data, int offset )
	{
		for( int i = 0; i < (blockSize >>> 3); ++i, offset += 8 )
		{
			state[ i ] ^= data.getLongLE( offset );
		}
		permutation();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary squeeze( int wantHashSize )
	{
		Binary hash = new Binary().reserve( wantHashSize );
		for( int i = 0; hash.size() < wantHashSize; ++i )
		{
			// Every blockLen bytes, perform Permutation
			if( (hash.size() > 0) && ((hash.size() % blockSize) == 0) )
			{
				permutation();
				i = 0;
			}
			hash.addLongLE( state[ i ] );
		}
		hash.resize( wantHashSize );
		return hash;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void permutation()
	{
		long[] A = state;

		long a00 = A[ 0], a01 = A[ 1], a02 = A[ 2], a03 = A[ 3], a04 = A[ 4];
		long a05 = A[ 5], a06 = A[ 6], a07 = A[ 7], a08 = A[ 8], a09 = A[ 9];
		long a10 = A[10], a11 = A[11], a12 = A[12], a13 = A[13], a14 = A[14];
		long a15 = A[15], a16 = A[16], a17 = A[17], a18 = A[18], a19 = A[19];
		long a20 = A[20], a21 = A[21], a22 = A[22], a23 = A[23], a24 = A[24];

		for (int i = 0; i < 24; i++)
		{
			// theta
			long c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
			long c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
			long c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
			long c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
			long c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

			long d1 = rotateLeft( c1, 1 ) ^ c4;
			long d2 = rotateLeft( c2, 1 ) ^ c0;
			long d3 = rotateLeft( c3, 1 ) ^ c1;
			long d4 = rotateLeft( c4, 1 ) ^ c2;
			long d0 = rotateLeft( c0, 1 ) ^ c3;

			a00 ^= d1; a05 ^= d1; a10 ^= d1; a15 ^= d1; a20 ^= d1;
			a01 ^= d2; a06 ^= d2; a11 ^= d2; a16 ^= d2; a21 ^= d2;
			a02 ^= d3; a07 ^= d3; a12 ^= d3; a17 ^= d3; a22 ^= d3;
			a03 ^= d4; a08 ^= d4; a13 ^= d4; a18 ^= d4; a23 ^= d4;
			a04 ^= d0; a09 ^= d0; a14 ^= d0; a19 ^= d0; a24 ^= d0;

			// rho/pi
			c1  = rotateLeft( a01, 1 );
			a01 = rotateLeft( a06, 44 );
			a06 = rotateLeft( a09, 20 );
			a09 = rotateLeft( a22, 61 );
			a22 = rotateLeft( a14, 39 );
			a14 = rotateLeft( a20, 18 );
			a20 = rotateLeft( a02, 62 );
			a02 = rotateLeft( a12, 43 );
			a12 = rotateLeft( a13, 25 );
			a13 = rotateLeft( a19,  8 );
			a19 = rotateLeft( a23, 56 );
			a23 = rotateLeft( a15, 41 );
			a15 = rotateLeft( a04, 27 );
			a04 = rotateLeft( a24, 14 );
			a24 = rotateLeft( a21,  2 );
			a21 = rotateLeft( a08, 55 );
			a08 = rotateLeft( a16, 45 );
			a16 = rotateLeft( a05, 36 );
			a05 = rotateLeft( a03, 28 );
			a03 = rotateLeft( a18, 21 );
			a18 = rotateLeft( a17, 15 );
			a17 = rotateLeft( a11, 10 );
			a11 = rotateLeft( a07,  6 );
			a07 = rotateLeft( a10,  3 );
			a10 = c1;

			// chi
			c0 = a00 ^ (~a01 & a02);
			c1 = a01 ^ (~a02 & a03);
			a02 ^= ~a03 & a04;
			a03 ^= ~a04 & a00;
			a04 ^= ~a00 & a01;
			a00 = c0;
			a01 = c1;

			c0 = a05 ^ (~a06 & a07);
			c1 = a06 ^ (~a07 & a08);
			a07 ^= ~a08 & a09;
			a08 ^= ~a09 & a05;
			a09 ^= ~a05 & a06;
			a05 = c0;
			a06 = c1;

			c0 = a10 ^ (~a11 & a12);
			c1 = a11 ^ (~a12 & a13);
			a12 ^= ~a13 & a14;
			a13 ^= ~a14 & a10;
			a14 ^= ~a10 & a11;
			a10 = c0;
			a11 = c1;

			c0 = a15 ^ (~a16 & a17);
			c1 = a16 ^ (~a17 & a18);
			a17 ^= ~a18 & a19;
			a18 ^= ~a19 & a15;
			a19 ^= ~a15 & a16;
			a15 = c0;
			a16 = c1;

			c0 = a20 ^ (~a21 & a22);
			c1 = a21 ^ (~a22 & a23);
			a22 ^= ~a23 & a24;
			a23 ^= ~a24 & a20;
			a24 ^= ~a20 & a21;
			a20 = c0;
			a21 = c1;

			// iota
			a00 ^= CONSTANTS[i];
		}

		A[ 0] = a00; A[ 1] = a01; A[ 2] = a02; A[ 3] = a03; A[ 4] = a04;
		A[ 5] = a05; A[ 6] = a06; A[ 7] = a07; A[ 8] = a08; A[ 9] = a09;
		A[10] = a10; A[11] = a11; A[12] = a12; A[13] = a13; A[14] = a14;
		A[15] = a15; A[16] = a16; A[17] = a17; A[18] = a18; A[19] = a19;
		A[20] = a20; A[21] = a21; A[22] = a22; A[23] = a23; A[24] = a24;
	}

}
