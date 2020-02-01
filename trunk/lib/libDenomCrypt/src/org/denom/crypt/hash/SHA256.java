// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import org.denom.Binary;

import static java.lang.Integer.rotateRight;

/**
 * Cryptographic hash function SHA-256.
 */
public class SHA256 extends IHash
{
	public final static int HASH_SIZE = 32;

	// -----------------------------------------------------------------------------------------------------------------
	public SHA256()
	{
		super( BLOCK_SIZE );
		reset();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String name()
	{
		return "SHA-256";
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int size()
	{
		return HASH_SIZE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SHA256 clone()
	{
		return new SHA256();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void reset()
	{
		super.reset();
		H[0] = 0x6a09e667;
		H[1] = 0xbb67ae85;
		H[2] = 0x3c6ef372;
		H[3] = 0xa54ff53a;
		H[4] = 0x510e527f;
		H[5] = 0x9b05688c;
		H[6] = 0x1f83d9ab;
		H[7] = 0x5be0cd19;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary getHash()
	{
		finish();

		Binary hash = new Binary().reserve( HASH_SIZE );
		for( int h : H )
			hash.addInt( h );

		reset();
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
	private int[] W = new int[ 64 ];
	protected int[] H = new int[8];

	private final static int BLOCK_SIZE = 64;

	private static final int[] CONSTANTS = { 
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Обработать данные из data поблочно, начиная со смещения offset.
	 * Будет обработано данных размером кратным BLOCK_SIZE и не более size.
	 */
	protected void processBlock( Binary data, int offset )
	{
		int a = H[0];
		int b = H[1];
		int c = H[2];
		int d = H[3];
		int e = H[4];
		int f = H[5];
		int g = H[6];
		int h = H[7];

		byte[] buf = data.getDataRef();
		for( int j = 0; j < 16; ++j, offset += 4 )
		{
			W[ j ] =   (buf[ offset     ] << 24)
					| ((buf[ offset + 1 ] & 0xFF) << 16)
					| ((buf[ offset + 2 ] & 0xFF) << 8)
					|  (buf[ offset + 3 ] & 0xFF);

			int s0 = rotateRight( a, 2 ) ^ rotateRight( a, 13 ) ^ rotateRight( a, 22 );
			int ma = (a & b) ^ (a & c) ^ (b & c);
			int t2 = s0 + ma;
			int s1 = rotateRight( e, 6 ) ^ rotateRight( e, 11 ) ^ rotateRight( e, 25 );
			int ch = (e & f) ^ (~e & g);
			int t1 = h + s1 + ch + CONSTANTS[ j ] + W[ j ];

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}

		for( int j = 16; j < 64; ++j )
		{
			int s0 = rotateRight( W[j - 15], 7 ) ^ rotateRight( W[j - 15], 18 ) ^ (W[j - 15] >>> 3);
			int s1 = rotateRight( W[j - 2], 17 ) ^ rotateRight( W[j - 2], 19 ) ^ (W[j - 2] >>> 10);
			W[j] = W[j - 16] + s0 + W[j - 7] + s1;

			s0 = rotateRight( a, 2 ) ^ rotateRight( a, 13 ) ^ rotateRight( a, 22 );
			int ma = (a & b) ^ (a & c) ^ (b & c);
			int t2 = s0 + ma;
			s1 = rotateRight( e, 6 ) ^ rotateRight( e, 11 ) ^ rotateRight( e, 25 );
			int ch = (e & f) ^ (~e & g);
			int t1 = h + s1 + ch + CONSTANTS[j] + W[j];

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}

		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;
	}

}
