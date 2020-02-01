package org.denom.crypt.ec.F2m.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Sect113 extends CustomF2mCurve
{
	private static final int ARR_LEN = 2;
	private static final int ARR_LEN2 = 4;

	private static final long M49 = -1L >>> 15;
	private static final long M57 = -1L >>> 7;


	public static Sect113 r1()
	{
		return new Sect113( "1.3.132.0.4",
			"003088250CA6E7C7FE649CE85820F7", // a
			"00E8BEE4D3E2260744188BE0E9C723", // b
			"0100000000000000D9CCEC8A39E56F", // order (n)
			"02", // cofactor(h)
			"04 009D73616F35F4AB1407D73562C10F 00A52830277958EE84D1315ED31886", // G point
			false );
	}

	public static Sect113 r2()
	{
		return new Sect113( "1.3.132.0.5",
			"00689918DBEC7E5A0DD6DFC0AA55C7", // a
			"0095E9A9EC9B297BD4BF36E059184F", // b
			"010000000000000108789B2496AF93", // order (n)
			"02", // cofactor(h)
			"04 01A57A6A7B26CA5EF52FCDB8164797 00B3ADC94ED1FE674C06E695BABA1D", // G point
			false );
	}
	
	private Sect113( String oid, String aHex, String bHex, String orderHex, String cofactorHex, String gPointHex, boolean isKoblitz )
	{
		super( 113, 9, 0, 0, ARR_LEN, isKoblitz );
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

			long t = arr[ 1 ] >>> 49;
			arr[ 0 ] ^= t ^ (t << 9);
			arr[ 1 ] &= M49;
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


		public ECElement multiply( ECElement b )
		{
			long[] z = new long[ ARR_LEN ];
			Sect113.multiply( arr, ((Element)b).arr, z );
			return new Element( z );
		}

		public ECElement multiplyPlusProduct( ECElement b, ECElement x, ECElement y )
		{
			long[] ax = this.arr, bx = ((Element)b).arr;
			long[] xx = ((Element)x).arr, yx = ((Element)y).arr;

			long[] tt = new long[ ARR_LEN2 ];
			Sect113.multiplyAddToExt( ax, bx, tt );
			Sect113.multiplyAddToExt( xx, yx, tt );

			long[] z = new long[ ARR_LEN ];
			Sect113.reduce( tt, z );
			return new Element( z );
		}

		public ECElement square()
		{
			long[] z = new long[ ARR_LEN ];
			Sect113.square( arr, z );
			return new Element( z );
		}

		public ECElement squarePlusProduct( ECElement x, ECElement y )
		{
			long[] ax = this.arr;
			long[] xx = ((Element)x).arr, yx = ((Element)y).arr;

			long[] tt = new long[ ARR_LEN2 ];
			Sect113.squareAddToExt( ax, tt );
			Sect113.multiplyAddToExt( xx, yx, tt );

			long[] z = new long[ ARR_LEN ];
			Sect113.reduce( tt, z );
			return new Element( z );
		}

		public ECElement squarePow( int pow )
		{
			if( pow < 1 )
			{
				return this;
			}

			long[] z = new long[ ARR_LEN ];
			Sect113.squareN( arr, pow, z );
			return new Element( z );
		}

		public int trace()
		{
			// Non-zero-trace bits: 0
			return (int)(arr[ 0 ]) & 1;
		}

		public ECElement invert()
		{
			long[] z = new long[ ARR_LEN ];
			Sect113.invert( arr, z );
			return new Element( z );
		}

		public ECElement sqrt()
		{
			long[] z = new long[ ARR_LEN ];
			Sect113.sqrt( arr, z );
			return new Element( z );
		}

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

		public int hashCode()
		{
			return 113009 ^ java.util.Arrays.hashCode( arr );
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
		squareN( t1, 28, t0 );
		multiply( t0, t1, t0 );
		squareN( t0, 56, t1 );
		multiply( t1, t0, t1 );
		square( t1, z );
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

		x1 ^= (x3 << 15) ^ (x3 << 24);
		x2 ^= (x3 >>> 49) ^ (x3 >>> 40);

		x0 ^= (x2 << 15) ^ (x2 << 24);
		x1 ^= (x2 >>> 49) ^ (x2 >>> 40);

		long t = x1 >>> 49;
		z[ 0 ] = x0 ^ t ^ (t << 9);
		z[ 1 ] = x1 & M49;
	}


	private static void sqrt( long[] x, long[] z )
	{
		long u0 = Nat.unshuffle( x[ 0 ] ), u1 = Nat.unshuffle( x[ 1 ] );
		long e0 = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
		long c0 = (u0 >>> 32) | (u1 & 0xFFFFFFFF00000000L);

		z[ 0 ] = e0 ^ (c0 << 57) ^ (c0 << 5);
		z[ 1 ] = (c0 >>> 7) ^ (c0 >>> 59);
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


	private static void implMultiply( long[] x, long[] y, long[] zz )
	{
		// "Three-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.

		long f0 = x[ 0 ], f1 = x[ 1 ];
		f1 = ((f0 >>> 57) ^ (f1 << 7)) & M57;
		f0 &= M57;

		long g0 = y[ 0 ], g1 = y[ 1 ];
		g1 = ((g0 >>> 57) ^ (g1 << 7)) & M57;
		g0 &= M57;

		long[] H = new long[ 6 ];

		implMulw( f0, g0, H, 0 ); // H(0)       57/56 bits
		implMulw( f1, g1, H, 2 ); // H(INF)     57/54 bits
		implMulw( f0 ^ f1, g0 ^ g1, H, 4 ); // H(1)       57/56 bits

		long r = H[ 1 ] ^ H[ 2 ];
		long z0 = H[ 0 ], z3 = H[ 3 ], z1 = H[ 4 ] ^ z0 ^ r, z2 = H[ 5 ] ^ z3 ^ r;

		zz[ 0 ] = z0 ^ (z1 << 57);
		zz[ 1 ] = (z1 >>> 7) ^ (z2 << 50);
		zz[ 2 ] = (z2 >>> 14) ^ (z3 << 43);
		zz[ 3 ] = (z3 >>> 21);
	}


	private static void implMulw( long x, long y, long[] z, int zOff )
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
		long g;
		long h = 0;
		long l = u[ j & 7 ];
		int k = 48;
		do
		{
			j = (int)(x >>> k);
			g = u[ j & 7 ] ^ u[ (j >>> 3) & 7 ] << 3 ^ u[ (j >>> 6) & 7 ] << 6;
			l ^= (g << k);
			h ^= (g >>> -k);
		}
		while( (k -= 9) > 0 );

		h ^= ((x & 0x0100804020100800L) & ((y << 7) >> 63)) >>> 8;

		z[ zOff ] = l & M57;
		z[ zOff + 1 ] = (l >>> 57) ^ (h << 7);
	}


	private static void implSquare( long[] x, long[] zz )
	{
		Nat.expand64To128( x[ 0 ], zz, 0 );
		Nat.expand64To128( x[ 1 ], zz, 2 );
	}

}
