package org.denom.crypt.ec.F2m.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Sect163 extends CustomF2mCurve
{
	private static final int ARR_LEN = 3;
	private static final int ARR_LEN2 = 6;

	private static final long M35 = -1L >>> 29;
	private static final long M55 = -1L >>> 9;
	private static final long[] ROOT_Z = new long[] { 0xB6DB6DB6DB6DB6B0L, 0x492492492492DB6DL, 0x492492492L };


	// K-163
	public static Sect163 k1()
	{
		return new Sect163( "1.3.132.0.1",
			"01", // a
			"01", // b
			"04000000000000000000020108A2E0CC0D99F8A5EF", // n
			"02", // h
			"04 02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8"
			+ " 0289070FB05D38FF58321F2E800536D538CCDAA3D9", // G point
			true );
	}


	public static Sect163 r1()
	{
		return new Sect163( "1.3.132.0.2",
			"07B6882CAAEFA84F9554FF8428BD88E246D2782AE2", // a
			"0713612DCDDCB40AAB946BDA29CA91F73AF958AFD9", // b
			"03FFFFFFFFFFFFFFFFFFFF48AAB689C29CA710279B", // n
			"02", // h
			"04 0369979697AB43897789566789567F787A7876A654"
			+ " 00435EDB42EFAFB2989D51FEFCE3C80988F41FF883", // G point
			false );
	}


	// B-163
	public static Sect163 r2()
	{
		return new Sect163( "1.3.132.0.15",
			"01", // a
			"020A601907B8C953CA1481EB10512F78744A3205FD", // b
			"040000000000000000000292FE77E70C12A4234C33", // n
			"02", // h
			"04 03F0EBA16286A2D57EA0991168D4994637E8343E36"
			+ " 00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1", // G point
			false );
	}


	private Sect163( String oid, String aHex, String bHex, String orderHex, String cofactorHex, String gPointHex, boolean isKoblitz )
	{
		super( 163, 3, 6, 7, ARR_LEN, isKoblitz );
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

			long t = arr[ 2 ] >>> 35;
			arr[ 0 ] ^= t ^ (t << 3) ^ (t << 6) ^ (t << 7);
			arr[ 2 ] &= M35;
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
			Sect163.multiply( arr, ((Element)b).arr, z );
			return new Element( z );
		}

		public ECElement multiplyPlusProduct( ECElement b, ECElement x, ECElement y )
		{
			long[] ax = this.arr, bx = ((Element)b).arr;
			long[] xx = ((Element)x).arr, yx = ((Element)y).arr;

			long[] tt = new long[ ARR_LEN2 ];
			Sect163.multiplyAddToExt( ax, bx, tt );
			Sect163.multiplyAddToExt( xx, yx, tt );

			long[] z = new long[ ARR_LEN ];
			Sect163.reduce( tt, z );
			return new Element( z );
		}

		public ECElement square()
		{
			long[] z = new long[ ARR_LEN ];
			Sect163.square( arr, z );
			return new Element( z );
		}

		public ECElement squarePlusProduct( ECElement x, ECElement y )
		{
			long[] ax = this.arr;
			long[] xx = ((Element)x).arr, yx = ((Element)y).arr;

			long[] tt = new long[ ARR_LEN2 ];
			Sect163.squareAddToExt( ax, tt );
			Sect163.multiplyAddToExt( xx, yx, tt );

			long[] z = new long[ ARR_LEN ];
			Sect163.reduce( tt, z );
			return new Element( z );
		}

		public ECElement squarePow( int pow )
		{
			if( pow < 1 )
			{
				return this;
			}

			long[] z = new long[ ARR_LEN ];
			Sect163.squareN( arr, pow, z );
			return new Element( z );
		}

		public int trace()
		{
			// Non-zero-trace bits: 0, 157
			return (int)(arr[ 0 ] ^ (arr[ 2 ] >>> 29)) & 1;
		}

		public ECElement invert()
		{
			long[] z = new long[ ARR_LEN ];
			Sect163.invert( arr, z );
			return new Element( z );
		}

		public ECElement sqrt()
		{
			long[] z = new long[ ARR_LEN ];
			Sect163.sqrt( arr, z );
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
			return 163763 ^ java.util.Arrays.hashCode( arr );
		}
	}

	// =================================================================================================================

	private static void invert( long[] x, long[] z )
	{
		MUST( !Nat.isZero64( x ) );

		// Itoh-Tsujii inversion with bases { 2, 3 }

		long[] t0 = new long[ ARR_LEN ];
		long[] t1 = new long[ ARR_LEN ];

		square( x, t0 );

		// 3 | 162
		squareN( t0, 1, t1 );
		multiply( t0, t1, t0 );
		squareN( t1, 1, t1 );
		multiply( t0, t1, t0 );

		// 3 | 54
		squareN( t0, 3, t1 );
		multiply( t0, t1, t0 );
		squareN( t1, 3, t1 );
		multiply( t0, t1, t0 );

		// 3 | 18
		squareN( t0, 9, t1 );
		multiply( t0, t1, t0 );
		squareN( t1, 9, t1 );
		multiply( t0, t1, t0 );

		// 3 | 6
		squareN( t0, 27, t1 );
		multiply( t0, t1, t0 );
		squareN( t1, 27, t1 );
		multiply( t0, t1, t0 );

		// 2 | 2
		squareN( t0, 81, t1 );
		multiply( t0, t1, z );
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
		long x0 = xx[ 0 ], x1 = xx[ 1 ], x2 = xx[ 2 ], x3 = xx[ 3 ], x4 = xx[ 4 ], x5 = xx[ 5 ];

		x2 ^= (x5 << 29) ^ (x5 << 32) ^ (x5 << 35) ^ (x5 << 36);
		x3 ^= (x5 >>> 35) ^ (x5 >>> 32) ^ (x5 >>> 29) ^ (x5 >>> 28);

		x1 ^= (x4 << 29) ^ (x4 << 32) ^ (x4 << 35) ^ (x4 << 36);
		x2 ^= (x4 >>> 35) ^ (x4 >>> 32) ^ (x4 >>> 29) ^ (x4 >>> 28);

		x0 ^= (x3 << 29) ^ (x3 << 32) ^ (x3 << 35) ^ (x3 << 36);
		x1 ^= (x3 >>> 35) ^ (x3 >>> 32) ^ (x3 >>> 29) ^ (x3 >>> 28);

		long t = x2 >>> 35;
		z[ 0 ] = x0 ^ t ^ (t << 3) ^ (t << 6) ^ (t << 7);
		z[ 1 ] = x1;
		z[ 2 ] = x2 & M35;
	}


	private static void sqrt( long[] x, long[] z )
	{
		long[] odd = new long[ ARR_LEN ];

		long u0, u1;
		u0 = Nat.unshuffle( x[ 0 ] );
		u1 = Nat.unshuffle( x[ 1 ] );
		long e0 = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
		odd[ 0 ] = (u0 >>> 32) | (u1 & 0xFFFFFFFF00000000L);

		u0 = Nat.unshuffle( x[ 2 ] );
		long e1 = (u0 & 0x00000000FFFFFFFFL);
		odd[ 1 ] = (u0 >>> 32);

		multiply( odd, ROOT_Z, z );

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
		long z0 = zz[ 0 ], z1 = zz[ 1 ], z2 = zz[ 2 ], z3 = zz[ 3 ], z4 = zz[ 4 ], z5 = zz[ 5 ];
		zz[ 0 ] = z0 ^ (z1 << 55);
		zz[ 1 ] = (z1 >>> 9) ^ (z2 << 46);
		zz[ 2 ] = (z2 >>> 18) ^ (z3 << 37);
		zz[ 3 ] = (z3 >>> 27) ^ (z4 << 28);
		zz[ 4 ] = (z4 >>> 36) ^ (z5 << 19);
		zz[ 5 ] = (z5 >>> 45);
	}


	private static void implMultiply( long[] x, long[] y, long[] zz )
	{
		// "Five-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.

		long f0 = x[ 0 ], f1 = x[ 1 ], f2 = x[ 2 ];
		f2 = ((f1 >>> 46) ^ (f2 << 18));
		f1 = ((f0 >>> 55) ^ (f1 << 9)) & M55;
		f0 &= M55;

		long g0 = y[ 0 ], g1 = y[ 1 ], g2 = y[ 2 ];
		g2 = ((g1 >>> 46) ^ (g2 << 18));
		g1 = ((g0 >>> 55) ^ (g1 << 9)) & M55;
		g0 &= M55;

		long[] H = new long[ 10 ];

		implMulw( f0, g0, H, 0 ); // H(0)       55/54 bits
		implMulw( f2, g2, H, 2 ); // H(INF)     55/50 bits

		long t0 = f0 ^ f1 ^ f2;
		long t1 = g0 ^ g1 ^ g2;

		implMulw( t0, t1, H, 4 ); // H(1)       55/54 bits

		long t2 = (f1 << 1) ^ (f2 << 2);
		long t3 = (g1 << 1) ^ (g2 << 2);

		implMulw( f0 ^ t2, g0 ^ t3, H, 6 ); // H(t)       55/56 bits
		implMulw( t0 ^ t2, t1 ^ t3, H, 8 ); // H(t + 1)   55/56 bits

		long t4 = H[ 6 ] ^ H[ 8 ];
		long t5 = H[ 7 ] ^ H[ 9 ];

		// Calculate V
		long v0 = (t4 << 1) ^ H[ 6 ];
		long v1 = t4 ^ (t5 << 1) ^ H[ 7 ];
		long v2 = t5;

		// Calculate U
		long u0 = H[ 0 ];
		long u1 = H[ 1 ] ^ H[ 0 ] ^ H[ 4 ];
		long u2 = H[ 1 ] ^ H[ 5 ];

		// Calculate W
		long w0 = u0 ^ v0 ^ (H[ 2 ] << 4) ^ (H[ 2 ] << 1);
		long w1 = u1 ^ v1 ^ (H[ 3 ] << 4) ^ (H[ 3 ] << 1);
		long w2 = u2 ^ v2;

		// Propagate carries
		w1 ^= (w0 >>> 55);
		w0 &= M55;
		w2 ^= (w1 >>> 55);
		w1 &= M55;

		// Divide W by t
		w0 = (w0 >>> 1) ^ ((w1 & 1L) << 54);
		w1 = (w1 >>> 1) ^ ((w2 & 1L) << 54);
		w2 = (w2 >>> 1);

		// Divide W by (t + 1)
		w0 ^= (w0 << 1);
		w0 ^= (w0 << 2);
		w0 ^= (w0 << 4);
		w0 ^= (w0 << 8);
		w0 ^= (w0 << 16);
		w0 ^= (w0 << 32);

		w0 &= M55;
		w1 ^= (w0 >>> 54);

		w1 ^= (w1 << 1);
		w1 ^= (w1 << 2);
		w1 ^= (w1 << 4);
		w1 ^= (w1 << 8);
		w1 ^= (w1 << 16);
		w1 ^= (w1 << 32);

		w1 &= M55;
		w2 ^= (w1 >>> 54);

		w2 ^= (w2 << 1);
		w2 ^= (w2 << 2);
		w2 ^= (w2 << 4);
		w2 ^= (w2 << 8);
		w2 ^= (w2 << 16);
		w2 ^= (w2 << 32);

		zz[0] = u0;
		zz[1] = u1 ^ w0      ^ H[2];
		zz[2] = u2 ^ w1 ^ w0 ^ H[3];
		zz[3] =      w2 ^ w1;
		zz[4] =           w2 ^ H[2];
		zz[5] =                H[3];

		implCompactExt( zz );
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
		long g, h = 0, l = u[j & 3];
		int k = 47;
		do
		{
			j  = (int)(x >>> k);
			g  = u[j & 7]
			   ^ u[(j >>> 3) & 7] << 3
			   ^ u[(j >>> 6) & 7] << 6;
			l ^= (g <<   k);
			h ^= (g >>> -k);
		}
		while ((k -= 9) > 0);


		z[ zOff ] = l & M55;
		z[ zOff + 1 ] = (l >>> 55) ^ (h << 9);
	}


	private static void implSquare( long[] x, long[] zz )
	{
		Nat.expand64To128( x[ 0 ], zz, 0 );
		Nat.expand64To128( x[ 1 ], zz, 2 );

		long x2 = x[ 2 ];
		zz[ 4 ] = Nat.expand32to64( (int)x2 );
		zz[ 5 ] = Nat.expand8to16( (int)(x2 >>> 32) ) & 0xFFFFFFFFL;
	}

}
