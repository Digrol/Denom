// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import java.util.Arrays;
import org.denom.Binary;

/**
 * Cryptographic hash function SHA-1.
 */
public class SHA1 extends IHash
{
	public final static int HASH_SIZE = 20;
	private final static int BLOCK_SIZE = 64;

	private int[] H = new int[ 5 ];
	private int[] W = new int[ 80 ];

	// -----------------------------------------------------------------------------------------------------------------
	public SHA1()
	{
		super( BLOCK_SIZE );
		reset();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String name()
	{
		return "SHA-1";
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int size()
	{
		return HASH_SIZE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SHA1 clone()
	{
		return new SHA1();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SHA1 cloneState()
	{
		SHA1 cloned = (SHA1)this.cloneStateBase();
		cloned.H = Arrays.copyOf( this.H, this.H.length );
		return cloned;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void reset()
	{
		super.reset();
		H[0] = 0x67452301;
		H[1] = 0xEFCDAB89;
		H[2] = 0x98BADCFE;
		H[3] = 0x10325476;
		H[4] = 0xC3D2E1F0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary getHash()
	{
		finish();

		Binary hash = new Binary().reserve( HASH_SIZE );
		for( int h : H )
			hash.addInt( h );

		return hash;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void finish()
	{
		tail.add( 0x80 );

		if( tail.size() > 56 )
		{	// no room for length
			tail.resize( BLOCK_SIZE );
			processBlock( tail, 0 );
			tail.clear();
		}

		tail.resize( BLOCK_SIZE );
		tail.setLong( tail.size() - 8, processedBytes << 3 );
		processBlock( tail, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void processBlock( final Binary data, int offset )
	{
		byte[] buf = data.getDataRef();

		for( int j = 0; j < 16; ++j )
		{
			W[ j ] = (buf[ offset ] << 24) | ((buf[ offset + 1 ] & 0xFF) << 16) | ((buf[ offset + 2 ] & 0xFF) << 8) | (buf[ offset + 3 ] & 0xFF);
			offset += 4;
		}

		for( int j = 16; j < 80; ++j )
		{
			int a = W[ j - 3 ] ^ W[ j - 8 ] ^ W[ j - 14 ] ^ W[ j - 16 ];
			W[ j ] = Integer.rotateLeft( a, 1 );
		}

		int A = H[0];
		int B = H[1];
		int C = H[2];
		int D = H[3];
		int E = H[4];

		for( int j = 0; j < 20; ++j )
		{
			int temp = 0x5A827999 + ((A << 5) | (A >>> 27)) + ((B & C) | (~B & D)) + E + W[ j ];
			E = D;
			D = C;
			C = Integer.rotateRight( B, 2 );
			B = A;
			A = temp;
		}

		for( int j = 20; j < 40; ++j )
		{
			int temp = 0x6ED9EBA1 + ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + E + W[ j ];
			E = D;
			D = C;
			C = Integer.rotateRight( B, 2 );
			B = A;
			A = temp;
		}

		for( int j = 40; j < 60; ++j )
		{
			int temp = 0x8F1BBCDC + ((A << 5) | (A >>> 27)) + ((B & C) | (B & D) | (C & D)) + E + W[ j ];
			E = D;
			D = C;
			C = Integer.rotateRight( B, 2 );
			B = A;
			A = temp;
		}

		for( int j = 60; j < 80; ++j )
		{
			int temp = 0xCA62C1D6 + ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + E + W[ j ];
			E = D;
			D = C;
			C = Integer.rotateRight( B, 2 );
			B = A;
			A = temp;
		}

		H[0] += A;
		H[1] += B;
		H[2] += C;
		H[3] += D;
		H[4] += E;
	}

}
