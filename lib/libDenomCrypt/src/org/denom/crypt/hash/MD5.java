// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import java.util.Arrays;
import org.denom.Binary;

import static java.lang.Integer.rotateLeft;

/**
 * Cryptographic hash function MD5.
 */
public class MD5 extends IHash
{
	public final static int HASH_SIZE = 16;
	private final static int BLOCK_SIZE = 64;

	private int[] H = new int[ 4 ];
	private int[] W = new int[ 16 ];

	// -----------------------------------------------------------------------------------------------------------------
	public MD5()
	{
		super( BLOCK_SIZE );
		reset();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String name()
	{
		return "MD5";
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int size()
	{
		return HASH_SIZE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public MD5 clone()
	{
		return new MD5();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public MD5 cloneState()
	{
		MD5 cloned = (MD5)this.cloneStateBase();
		cloned.H = Arrays.copyOf( this.H, this.H.length );
		return cloned;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void reset()
	{
		super.reset();
		H[0] = 0x67452301;
		H[1] = 0xefcdab89;
		H[2] = 0x98badcfe;
		H[3] = 0x10325476;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary getHash()
	{
		finish();

		Binary hash = new Binary( HASH_SIZE );
		for( int i = 0; i < H.length; ++i )
			hash.setIntLE( i << 2, H[ i ] );

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
		tail.setLongLE( tail.size() - 8, processedBytes << 3 );
		processBlock( tail, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void processBlock( final Binary data, int offset )
	{
		byte[] buf = data.getDataRef();
		for( int i = 0; i < 16; i++, offset += 4 )
		{
			W[ i ] =   (buf[ offset ] & 0xff)
					| ((buf[ offset + 1 ] & 0xff) << 8)
					| ((buf[ offset + 2 ] & 0xff) << 16)
					|  (buf[ offset + 3 ] << 24);
		}

		int a = H[0];
		int b = H[1];
		int c = H[2];
		int d = H[3];

		a = rotateLeft(a + ((b & c) | (~b & d)) +  W[0] + 0xd76aa478,  7) + b;
		d = rotateLeft(d + ((a & b) | (~a & c)) +  W[1] + 0xe8c7b756, 12) + a;
		c = rotateLeft(c + ((d & a) | (~d & b)) +  W[2] + 0x242070db, 17) + d;
		b = rotateLeft(b + ((c & d) | (~c & a)) +  W[3] + 0xc1bdceee, 22) + c;
		a = rotateLeft(a + ((b & c) | (~b & d)) +  W[4] + 0xf57c0faf,  7) + b;
		d = rotateLeft(d + ((a & b) | (~a & c)) +  W[5] + 0x4787c62a, 12) + a;
		c = rotateLeft(c + ((d & a) | (~d & b)) +  W[6] + 0xa8304613, 17) + d;
		b = rotateLeft(b + ((c & d) | (~c & a)) +  W[7] + 0xfd469501, 22) + c;
		a = rotateLeft(a + ((b & c) | (~b & d)) +  W[8] + 0x698098d8,  7) + b;
		d = rotateLeft(d + ((a & b) | (~a & c)) +  W[9] + 0x8b44f7af, 12) + a;
		c = rotateLeft(c + ((d & a) | (~d & b)) + W[10] + 0xffff5bb1, 17) + d;
		b = rotateLeft(b + ((c & d) | (~c & a)) + W[11] + 0x895cd7be, 22) + c;
		a = rotateLeft(a + ((b & c) | (~b & d)) + W[12] + 0x6b901122,  7) + b;
		d = rotateLeft(d + ((a & b) | (~a & c)) + W[13] + 0xfd987193, 12) + a;
		c = rotateLeft(c + ((d & a) | (~d & b)) + W[14] + 0xa679438e, 17) + d;
		b = rotateLeft(b + ((c & d) | (~c & a)) + W[15] + 0x49b40821, 22) + c;

		a = rotateLeft(a + ((b & d) | (c & ~d)) +  W[1] + 0xf61e2562,  5) + b;
		d = rotateLeft(d + ((a & c) | (b & ~c)) +  W[6] + 0xc040b340,  9) + a;
		c = rotateLeft(c + ((d & b) | (a & ~b)) + W[11] + 0x265e5a51, 14) + d;
		b = rotateLeft(b + ((c & a) | (d & ~a)) +  W[0] + 0xe9b6c7aa, 20) + c;
		a = rotateLeft(a + ((b & d) | (c & ~d)) +  W[5] + 0xd62f105d,  5) + b;
		d = rotateLeft(d + ((a & c) | (b & ~c)) + W[10] + 0x02441453,  9) + a;
		c = rotateLeft(c + ((d & b) | (a & ~b)) + W[15] + 0xd8a1e681, 14) + d;
		b = rotateLeft(b + ((c & a) | (d & ~a)) +  W[4] + 0xe7d3fbc8, 20) + c;
		a = rotateLeft(a + ((b & d) | (c & ~d)) +  W[9] + 0x21e1cde6,  5) + b;
		d = rotateLeft(d + ((a & c) | (b & ~c)) + W[14] + 0xc33707d6,  9) + a;
		c = rotateLeft(c + ((d & b) | (a & ~b)) +  W[3] + 0xf4d50d87, 14) + d;
		b = rotateLeft(b + ((c & a) | (d & ~a)) +  W[8] + 0x455a14ed, 20) + c;
		a = rotateLeft(a + ((b & d) | (c & ~d)) + W[13] + 0xa9e3e905,  5) + b;
		d = rotateLeft(d + ((a & c) | (b & ~c)) +  W[2] + 0xfcefa3f8,  9) + a;
		c = rotateLeft(c + ((d & b) | (a & ~b)) +  W[7] + 0x676f02d9, 14) + d;
		b = rotateLeft(b + ((c & a) | (d & ~a)) + W[12] + 0x8d2a4c8a, 20) + c;

		a = rotateLeft(a + (b ^ c ^ d) +  W[5] + 0xfffa3942,  4) + b;
		d = rotateLeft(d + (a ^ b ^ c) +  W[8] + 0x8771f681, 11) + a;
		c = rotateLeft(c + (d ^ a ^ b) + W[11] + 0x6d9d6122, 16) + d;
		b = rotateLeft(b + (c ^ d ^ a) + W[14] + 0xfde5380c, 23) + c;
		a = rotateLeft(a + (b ^ c ^ d) +  W[1] + 0xa4beea44,  4) + b;
		d = rotateLeft(d + (a ^ b ^ c) +  W[4] + 0x4bdecfa9, 11) + a;
		c = rotateLeft(c + (d ^ a ^ b) +  W[7] + 0xf6bb4b60, 16) + d;
		b = rotateLeft(b + (c ^ d ^ a) + W[10] + 0xbebfbc70, 23) + c;
		a = rotateLeft(a + (b ^ c ^ d) + W[13] + 0x289b7ec6,  4) + b;
		d = rotateLeft(d + (a ^ b ^ c) +  W[0] + 0xeaa127fa, 11) + a;
		c = rotateLeft(c + (d ^ a ^ b) +  W[3] + 0xd4ef3085, 16) + d;
		b = rotateLeft(b + (c ^ d ^ a) +  W[6] + 0x04881d05, 23) + c;
		a = rotateLeft(a + (b ^ c ^ d) +  W[9] + 0xd9d4d039,  4) + b;
		d = rotateLeft(d + (a ^ b ^ c) + W[12] + 0xe6db99e5, 11) + a;
		c = rotateLeft(c + (d ^ a ^ b) + W[15] + 0x1fa27cf8, 16) + d;
		b = rotateLeft(b + (c ^ d ^ a) +  W[2] + 0xc4ac5665, 23) + c;

		a = rotateLeft(a + (c ^ (b | ~d)) +  W[0] + 0xf4292244,  6) + b;
		d = rotateLeft(d + (b ^ (a | ~c)) +  W[7] + 0x432aff97, 10) + a;
		c = rotateLeft(c + (a ^ (d | ~b)) + W[14] + 0xab9423a7, 15) + d;
		b = rotateLeft(b + (d ^ (c | ~a)) +  W[5] + 0xfc93a039, 21) + c;
		a = rotateLeft(a + (c ^ (b | ~d)) + W[12] + 0x655b59c3,  6) + b;
		d = rotateLeft(d + (b ^ (a | ~c)) +  W[3] + 0x8f0ccc92, 10) + a;
		c = rotateLeft(c + (a ^ (d | ~b)) + W[10] + 0xffeff47d, 15) + d;
		b = rotateLeft(b + (d ^ (c | ~a)) +  W[1] + 0x85845dd1, 21) + c;
		a = rotateLeft(a + (c ^ (b | ~d)) +  W[8] + 0x6fa87e4f,  6) + b;
		d = rotateLeft(d + (b ^ (a | ~c)) + W[15] + 0xfe2ce6e0, 10) + a;
		c = rotateLeft(c + (a ^ (d | ~b)) +  W[6] + 0xa3014314, 15) + d;
		b = rotateLeft(b + (d ^ (c | ~a)) + W[13] + 0x4e0811a1, 21) + c;
		a = rotateLeft(a + (c ^ (b | ~d)) +  W[4] + 0xf7537e82,  6) + b;
		d = rotateLeft(d + (b ^ (a | ~c)) + W[11] + 0xbd3af235, 10) + a;
		c = rotateLeft(c + (a ^ (d | ~b)) +  W[2] + 0x2ad7d2bb, 15) + d;
		b = rotateLeft(b + (d ^ (c | ~a)) +  W[9] + 0xeb86d391, 21) + c;

		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
	}

}
