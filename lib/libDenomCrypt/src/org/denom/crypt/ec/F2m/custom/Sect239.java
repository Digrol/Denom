package org.denom.crypt.ec.F2m.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Sect239 extends CustomF2mCurve
{
	private static final int ARR_LEN = 4;
	private static final int ARR_LEN2 = 8;

	private static final long M47 = -1L >>> 17;
	private static final long M60 = -1L >>> 4;


	public static Sect239 k1()
	{
		return new Sect239( "1.3.132.0.3",
			"00", // a
			"01", // b
			"2000000000000000000000000000005A79FEC67CB6E91F1C1DA800E478A5", // n
			"04", // h
			"04 29A0B6A887A983E9730988A68727A8B2D126C44CC2CC7B2A6555193035DC"
			+ " 76310804F12E549BDB011C103089E73510ACB275FC312A5DC6B76553F0CA", // G point
			true );
	}


	private Sect239( String oid, String aHex, String bHex, String orderHex, String cofactorHex, String gPointHex, boolean isKoblitz )
	{
		super( 239, 158, 0, 0, ARR_LEN, isKoblitz );
		super.init( new Element(), new Point( null, null, null ), oid, aHex, bHex, orderHex, cofactorHex, gPointHex );
	}


	// =================================================================================================================
	// ELEMENT
	// =================================================================================================================
	private class Element extends CustomF2mCurve.Element
	{
		private Element() {}

		private Element( BigInteger X )
		{
			super( X );

			long t = arr[ 3 ] >>> 47;
			arr[ 0 ] ^= t;
			arr[ 2 ] ^= (t << 30);
			arr[ 3 ] &= M47;
		}

		private Element( long[] x )
		{
			super( x );
		}

		@Override
		public ECElement create( BigInteger x )
		{
			return new Element( x );
		}

		@Override
		protected Element create( long[] x )
		{
			return new Element( x );
		}

		@Override
		public ECElement multiply( ECElement b )
		{
			long[] z = new long[ ARR_LEN ];
			Sect239.multiply( arr, ((Element)b).arr, z );
			return new Element( z );
		}

		@Override
		public ECElement multiplyPlusProduct( ECElement b, ECElement x, ECElement y )
		{
			long[] ax = this.arr;
			long[] bx = ((Element)b).arr;
			long[] xx = ((Element)x).arr;
			long[] yx = ((Element)y).arr;

			long[] tt = new long[ ARR_LEN2 ];
			Sect239.multiplyAddToExt( ax, bx, tt );
			Sect239.multiplyAddToExt( xx, yx, tt );

			long[] z = new long[ ARR_LEN ];
			Sect239.reduce( tt, z );
			return new Element( z );
		}

		@Override
		public ECElement square()
		{
			long[] z = new long[ ARR_LEN ];
			Sect239.square( arr, z );
			return new Element( z );
		}

		@Override
		public ECElement squarePlusProduct( ECElement x, ECElement y )
		{
			long[] ax = this.arr;
			long[] xx = ((Element)x).arr, yx = ((Element)y).arr;

			long[] tt = new long[ ARR_LEN2 ];
			Sect239.squareAddToExt( ax, tt );
			Sect239.multiplyAddToExt( xx, yx, tt );

			long[] z = new long[ ARR_LEN ];
			Sect239.reduce( tt, z );
			return new Element( z );
		}

		@Override
		public ECElement squarePow( int pow )
		{
			if( pow < 1 )
			{
				return this;
			}

			long[] z = new long[ ARR_LEN ];
			Sect239.squareN( arr, pow, z );
			return new Element( z );
		}

		@Override
		public int trace()
		{
			// Non-zero-trace bits: 0, 81, 162
			return (int)(arr[ 0 ] ^ (arr[ 1 ] >>> 17) ^ (arr[ 2 ] >>> 34)) & 1;
		}

		@Override
		public ECElement invert()
		{
			long[] z = new long[ ARR_LEN ];
			Sect239.invert( arr, z );
			return new Element( z );
		}

		@Override
		public ECElement sqrt()
		{
			long[] z = new long[ ARR_LEN ];
			Sect239.sqrt( arr, z );
			return new Element( z );
		}

		@Override
		public boolean equals( Object other )
		{
			if( other == this )
			{
				return true;
			}

			if( !(other instanceof Element) )
			{
				return false;
			}

			Element o = (Element)other;
			return Arrays.equals( arr, o.arr );
		}

		@Override
		public int hashCode()
		{
			return 23900158 ^ java.util.Arrays.hashCode( arr );
		}
	}

	// =================================================================================================================

	private static void invert( long[] x, long[] z )
	{
		MUST( !Nat.isZero64( x ) );

		// Itoh-Tsujii inversion

		long[] t0 = new long[ ARR_LEN ];
		long[] t1 = new long[ ARR_LEN ];

		square( x, t0 );
		multiply( t0, x, t0 );
		square( t0, t0 );
		multiply( t0, x, t0 );
		squareN( t0, 3, t1 );
		multiply( t1, t0, t1 );
		square( t1, t1 );
		multiply( t1, x, t1 );
		squareN( t1, 7, t0 );
		multiply( t0, t1, t0 );
		squareN( t0, 14, t1 );
		multiply( t1, t0, t1 );
		square( t1, t1 );
		multiply( t1, x, t1 );
		squareN( t1, 29, t0 );
		multiply( t0, t1, t0 );
		square( t0, t0 );
		multiply( t0, x, t0 );
		squareN( t0, 59, t1 );
		multiply( t1, t0, t1 );
		square( t1, t1 );
		multiply( t1, x, t1 );
		squareN( t1, 119, t0 );
		multiply( t0, t1, t0 );
		square( t0, z );
	}


	private static void multiply( long[] x, long[] y, long[] z )
	{
		long[] tt = new long[ ARR_LEN2 ];
		implMultiply( x, y, tt );
		reduce( tt, z );
	}


	private static void multiplyAddToExt( long[] x, long[] y, long[] zz )
	{
		long[] tt = new long[ ARR_LEN2 ];
		implMultiply( x, y, tt );
		add( zz, tt, zz );
	}


	private static void reduce( long[] xx, long[] z )
	{
		long x0 = xx[ 0 ], x1 = xx[ 1 ], x2 = xx[ 2 ], x3 = xx[ 3 ];
		long x4 = xx[ 4 ], x5 = xx[ 5 ], x6 = xx[ 6 ], x7 = xx[ 7 ];

		x3 ^= (x7 << 17);
		x4 ^= (x7 >>> 47);
		x5 ^= (x7 << 47);
		x6 ^= (x7 >>> 17);

		x2 ^= (x6 << 17);
		x3 ^= (x6 >>> 47);
		x4 ^= (x6 << 47);
		x5 ^= (x6 >>> 17);

		x1 ^= (x5 << 17);
		x2 ^= (x5 >>> 47);
		x3 ^= (x5 << 47);
		x4 ^= (x5 >>> 17);

		x0 ^= (x4 << 17);
		x1 ^= (x4 >>> 47);
		x2 ^= (x4 << 47);
		x3 ^= (x4 >>> 17);

		long t = x3 >>> 47;
		z[ 0 ] = x0 ^ t;
		z[ 1 ] = x1;
		z[ 2 ] = x2 ^ (t << 30);
		z[ 3 ] = x3 & M47;
	}


	private static void sqrt( long[] x, long[] z )
	{
		long u0, u1;
		u0 = Nat.unshuffle( x[ 0 ] );
		u1 = Nat.unshuffle( x[ 1 ] );
		long e0 = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
		long c0 = (u0 >>> 32) | (u1 & 0xFFFFFFFF00000000L);

		u0 = Nat.unshuffle( x[ 2 ] );
		u1 = Nat.unshuffle( x[ 3 ] );
		long e1 = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
		long c1 = (u0 >>> 32) | (u1 & 0xFFFFFFFF00000000L);

		long c2, c3;
		c3 = (c1 >>> 49);
		c2 = (c0 >>> 49) | (c1 << 15);
		c1 ^= (c0 << 15);

		long[] tt = new long[ ARR_LEN2 ];

		int[] shifts = { 39, 120 };
		for( int i = 0; i < shifts.length; ++i )
		{
			int w = shifts[ i ] >>> 6, s = shifts[ i ] & 63;
			tt[ w ] ^= (c0 << s);
			tt[ w + 1 ] ^= (c1 << s) | (c0 >>> -s);
			tt[ w + 2 ] ^= (c2 << s) | (c1 >>> -s);
			tt[ w + 3 ] ^= (c3 << s) | (c2 >>> -s);
			tt[ w + 4 ] ^= (c3 >>> -s);
		}

		reduce( tt, z );

		z[ 0 ] ^= e0;
		z[ 1 ] ^= e1;
	}


	private static void square( long[] x, long[] z )
	{
		long[] tt = new long[ ARR_LEN2 ];
		implSquare( x, tt );
		reduce( tt, z );
	}


	private static void squareAddToExt( long[] x, long[] zz )
	{
		long[] tt = new long[ ARR_LEN2 ];
		implSquare( x, tt );
		add( zz, tt, zz );
	}


	private static void squareN( long[] x, int n, long[] z )
	{
		long[] tt = new long[ ARR_LEN2 ];
		implSquare( x, tt );
		reduce( tt, z );

		while( --n > 0 )
		{
			implSquare( z, tt );
			reduce( tt, z );
		}
	}


	private static void implCompactExt( long[] zz )
	{
		long z0 = zz[ 0 ], z1 = zz[ 1 ], z2 = zz[ 2 ], z3 = zz[ 3 ], z4 = zz[ 4 ];
		long z5 = zz[ 5 ], z6 = zz[ 6 ], z7 = zz[ 7 ];
		zz[ 0 ] = z0 ^ (z1 << 60);
		zz[ 1 ] = (z1 >>> 4) ^ (z2 << 56);
		zz[ 2 ] = (z2 >>> 8) ^ (z3 << 52);
		zz[ 3 ] = (z3 >>> 12) ^ (z4 << 48);
		zz[ 4 ] = (z4 >>> 16) ^ (z5 << 44);
		zz[ 5 ] = (z5 >>> 20) ^ (z6 << 40);
		zz[ 6 ] = (z6 >>> 24) ^ (z7 << 36);
		zz[ 7 ] = (z7 >>> 28);
	}


	private static void implExpand( long[] x, long[] z )
	{
		long x0 = x[ 0 ], x1 = x[ 1 ], x2 = x[ 2 ], x3 = x[ 3 ];
		z[ 0 ] = x0 & M60;
		z[ 1 ] = ((x0 >>> 60) ^ (x1 << 4)) & M60;
		z[ 2 ] = ((x1 >>> 56) ^ (x2 << 8)) & M60;
		z[ 3 ] = ((x2 >>> 52) ^ (x3 << 12));
	}


	private static void implMultiply( long[] x, long[] y, long[] zz )
	{
		// "Two-level seven-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.

		long[] f = new long[ 4 ], g = new long[ 4 ];
		implExpand( x, f );
		implExpand( y, g );

		implMulwAcc( f[ 0 ], g[ 0 ], zz, 0 );
		implMulwAcc( f[ 1 ], g[ 1 ], zz, 1 );
		implMulwAcc( f[ 2 ], g[ 2 ], zz, 2 );
		implMulwAcc( f[ 3 ], g[ 3 ], zz, 3 );

		// U *= (1 - t^n)
		for( int i = 5; i > 0; --i )
		{
			zz[ i ] ^= zz[ i - 1 ];
		}

		implMulwAcc( f[ 0 ] ^ f[ 1 ], g[ 0 ] ^ g[ 1 ], zz, 1 );
		implMulwAcc( f[ 2 ] ^ f[ 3 ], g[ 2 ] ^ g[ 3 ], zz, 3 );

		// V *= (1 - t^2n)
		for( int i = 7; i > 1; --i )
		{
			zz[ i ] ^= zz[ i - 2 ];
		}

		// Double-length recursion
		{
			long c0 = f[ 0 ] ^ f[ 2 ], c1 = f[ 1 ] ^ f[ 3 ];
			long d0 = g[ 0 ] ^ g[ 2 ], d1 = g[ 1 ] ^ g[ 3 ];
			implMulwAcc( c0 ^ c1, d0 ^ d1, zz, 3 );
			long[] t = new long[ 3 ];
			implMulwAcc( c0, d0, t, 0 );
			implMulwAcc( c1, d1, t, 1 );
			long t0 = t[ 0 ], t1 = t[ 1 ], t2 = t[ 2 ];
			zz[ 2 ] ^= t0;
			zz[ 3 ] ^= t0 ^ t1;
			zz[ 4 ] ^= t2 ^ t1;
			zz[ 5 ] ^= t2;
		}

		implCompactExt( zz );
	}


	private static void implMulwAcc( long x, long y, long[] z, int zOff )
	{
		long[] u = new long[ 8 ];
		// u[0] = 0;
		u[ 1 ] = y;
		u[ 2 ] = u[ 1 ] << 1;
		u[ 3 ] = u[ 2 ] ^ y;
		u[ 4 ] = u[ 2 ] << 1;
		u[ 5 ] = u[ 4 ] ^ y;
		u[ 6 ] = u[ 3 ] << 1;
		u[ 7 ] = u[ 6 ] ^ y;

		int j = (int)x;
		long g, h = 0, l = u[ j & 7 ] ^ (u[ (j >>> 3) & 7 ] << 3);
		int k = 54;
		do
		{
			j = (int)(x >>> k);
			g = u[ j & 7 ] ^ u[ (j >>> 3) & 7 ] << 3;
			l ^= (g << k);
			h ^= (g >>> -k);
		}
		while( (k -= 6) > 0 );

		h ^= ((x & 0x0820820820820820L) & ((y << 4) >> 63)) >>> 5;

		z[ zOff ] ^= l & M60;
		z[ zOff + 1 ] ^= (l >>> 60) ^ (h << 4);
	}


	private static void implSquare( long[] x, long[] zz )
	{
		Nat.expand64To128( x[ 0 ], zz, 0 );
		Nat.expand64To128( x[ 1 ], zz, 2 );
		Nat.expand64To128( x[ 2 ], zz, 4 );

		long x3 = x[ 3 ];
		zz[ 6 ] = Nat.expand32to64( (int)x3 );
		zz[ 7 ] = Nat.expand16to32( (int)(x3 >>> 32) ) & 0xFFFFFFFFL;
	}

}
