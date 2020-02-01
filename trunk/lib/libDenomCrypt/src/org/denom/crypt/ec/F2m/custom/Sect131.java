package org.denom.crypt.ec.F2m.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Sect131 extends CustomF2mCurve
{
	private static final int ARR_LEN = 3;
	private static final int ARR_LEN2 = 6;

	private static final long M03 = -1L >>> 61;
	private static final long M44 = -1L >>> 20;
	private static final long[] ROOT_Z = new long[]{ 0x26BC4D789AF13523L, 0x26BC4D789AF135E2L, 0x6L };

	protected Point infinity;


	public static Sect131 r1()
	{
		return new Sect131( "1.3.132.0.22",
			"07A11B09A76B562144418FF3FF8C2570B8", // a
			"0217C05610884B63B9C6C7291678F9D341", // b
			"0400000000000000023123953A9464B54D", // n
			"02", // h
			"04 0081BAF91FDF9833C40F9C181343638399"
			+ " 078C6E7EA38C001F73C8134B1B4EF9E150", // G point
			false );
	}


	public static Sect131 r2()
	{
		return new Sect131( "1.3.132.0.23",
			"03E5A88919D7CAFCBF415F07C2176573B2", // a
			"04B8266A46C55657AC734CE38F018F2192", // b
			"0400000000000000016954A233049BA98F", // n
			"02", // h
			"04 0356DCD8F2F95031AD652D23951BB366A8"
			+ " 0648F06D867940A5366D9E265DE9EB240F", // G point
			false );
	}


	private Sect131( String oid, String aHex, String bHex, String orderHex, String cofactorHex, String gPointHex, boolean isKoblitz )
	{
		super( 131, 2, 3, 8, ARR_LEN, isKoblitz );
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

			long t = arr[ 2 ] >>> 3;
			arr[ 0 ] ^= t ^ (t << 2) ^ (t << 3) ^ (t << 8);
			arr[ 1 ] ^= (t >>> 56);
			arr[ 2 ] &= M03;
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
			Sect131.multiply( arr, ((Element)b).arr, z );
			return new Element( z );
		}

		public ECElement multiplyPlusProduct( ECElement b, ECElement x, ECElement y )
		{
			long[] ax = this.arr, bx = ((Element)b).arr;
			long[] xx = ((Element)x).arr, yx = ((Element)y).arr;

			long[] tt = new long[ 5 ];
			Sect131.multiplyAddToExt( ax, bx, tt );
			Sect131.multiplyAddToExt( xx, yx, tt );

			long[] z = new long[ ARR_LEN ];
			Sect131.reduce( tt, z );
			return new Element( z );
		}

		public ECElement square()
		{
			long[] z = new long[ ARR_LEN ];
			Sect131.square( arr, z );
			return new Element( z );
		}

		public ECElement squarePlusProduct( ECElement x, ECElement y )
		{
			long[] ax = this.arr;
			long[] xx = ((Element)x).arr, yx = ((Element)y).arr;

			long[] tt = new long[ 5 ];
			Sect131.squareAddToExt( ax, tt );
			Sect131.multiplyAddToExt( xx, yx, tt );

			long[] z = new long[ ARR_LEN ];
			Sect131.reduce( tt, z );
			return new Element( z );
		}

		public ECElement squarePow( int pow )
		{
			if( pow < 1 )
			{
				return this;
			}

			long[] z = new long[ ARR_LEN ];
			Sect131.squareN( arr, pow, z );
			return new Element( z );
		}

		public int trace()
		{
			// Non-zero-trace bits: 0, 123, 129
			return (int)(arr[0] ^ (arr[1] >>> 59) ^ (arr[2] >>> 1)) & 1;
		}

		public ECElement invert()
		{
			long[] z = new long[ ARR_LEN ];
			Sect131.invert( arr, z );
			return new Element( z );
		}

		public ECElement sqrt()
		{
			long[] z = new long[ ARR_LEN ];
			Sect131.sqrt( arr, z );
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
			return 131832 ^ java.util.Arrays.hashCode( arr );
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
		squareN( t0, 2, t1 );
		multiply( t1, t0, t1 );
		squareN( t1, 4, t0 );
		multiply( t0, t1, t0 );
		squareN( t0, 8, t1 );
		multiply( t1, t0, t1 );
		squareN( t1, 16, t0 );
		multiply( t0, t1, t0 );
		squareN( t0, 32, t1 );
		multiply( t1, t0, t1 );
		square( t1, t1 );
		multiply( t1, x, t1 );
		squareN( t1, 65, t0 );
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
		long x0 = xx[0], x1 = xx[1], x2 = xx[2], x3 = xx[3], x4 = xx[4];

		x1 ^= (x4 <<  61) ^ (x4 <<  63);
		x2 ^= (x4 >>>  3) ^ (x4 >>>  1) ^ x4 ^ (x4 <<   5);
		x3 ^=                                  (x4 >>> 59);

		x0 ^= (x3 <<  61) ^ (x3 <<  63);
		x1 ^= (x3 >>>  3) ^ (x3 >>>  1) ^ x3 ^ (x3 <<   5);
		x2 ^=                                  (x3 >>> 59);

		long t = x2 >>> 3;
		z[0]   = x0 ^ t ^ (t << 2) ^ (t << 3) ^ (t <<   8);
		z[1]   = x1                           ^ (t >>> 56);
		z[2]   = x2 & M03;
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
		long[] tt = new long[ 5 ];
		implSquare( x, tt );
		reduce( tt, z );
	}


	private static void squareAddToExt( long[] x, long[] zz )
	{
		long[] tt = new long[ 5 ];
		implSquare( x, tt );
		add( zz, tt, zz );
	}


	private static void squareN( long[] x, int n, long[] z )
	{
		long[] tt = new long[ 5 ];
		implSquare( x, tt );
		reduce( tt, z );

		while( --n > 0 )
		{
			implSquare( z, tt );
			reduce( tt, z );
		}
	}


	private static void implCompactExt(long[] zz)
	{
		long z0 = zz[0], z1 = zz[1], z2 = zz[2], z3 = zz[3], z4 = zz[4], z5 = zz[5];
		zz[0] =  z0         ^ (z1 << 44);
		zz[1] = (z1 >>> 20) ^ (z2 << 24);
		zz[2] = (z2 >>> 40) ^ (z3 <<  4)
		                    ^ (z4 << 48);
		zz[3] = (z3 >>> 60) ^ (z5 << 28)
		      ^ (z4 >>> 16);
		zz[4] = (z5 >>> 36);
		zz[5] = 0;
	}

	private static void implMultiply(long[] x, long[] y, long[] zz)
	{
		// "Five-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
		
		long f0 = x[0], f1 = x[1], f2 = x[2];
		f2  = ((f1 >>> 24) ^ (f2 << 40)) & M44;
		f1  = ((f0 >>> 44) ^ (f1 << 20)) & M44;
		f0 &= M44;
		
		long g0 = y[0], g1 = y[1], g2 = y[2];
		g2  = ((g1 >>> 24) ^ (g2 << 40)) & M44;
		g1  = ((g0 >>> 44) ^ (g1 << 20)) & M44;
		g0 &= M44;
		
		long[] H = new long[10];
		
		implMulw(f0, g0, H, 0);           // H(0)       44/43 bits
		implMulw(f2, g2, H, 2);           // H(INF)     44/41 bits
		
		long t0 = f0 ^ f1 ^ f2;
		long t1 = g0 ^ g1 ^ g2;

		implMulw(t0, t1, H, 4);           // H(1)       44/43 bits

		long t2 = (f1 << 1) ^ (f2 << 2);
		long t3 = (g1 << 1) ^ (g2 << 2);
		
		implMulw(f0 ^ t2, g0 ^ t3, H, 6); // H(t)       44/45 bits
		implMulw(t0 ^ t2, t1 ^ t3, H, 8); // H(t + 1)   44/45 bits
		
		long t4 = H[6] ^ H[8];
		long t5 = H[7] ^ H[9];
		
		// Calculate V
		long v0 =      (t4 << 1) ^ H[6];
		long v1 = t4 ^ (t5 << 1) ^ H[7];
		long v2 = t5;
		
		// Calculate U
		long u0 = H[0];
		long u1 = H[1] ^ H[0] ^ H[4];
		long u2 =        H[1] ^ H[5];
		
		// Calculate W
		long w0 = u0 ^ v0 ^ (H[2] << 4) ^ (H[2] << 1);
		long w1 = u1 ^ v1 ^ (H[3] << 4) ^ (H[3] << 1);
		long w2 = u2 ^ v2;
		
		// Propagate carries
		w1 ^= (w0 >>> 44); w0 &= M44;
		w2 ^= (w1 >>> 44); w1 &= M44;
		
		// Divide W by t
		w0 = (w0 >>> 1) ^ ((w1 & 1L) << 43);
		w1 = (w1 >>> 1) ^ ((w2 & 1L) << 43);
		w2 = (w2 >>> 1);
		
		// Divide W by (t + 1)
		w0 ^= (w0 << 1);
		w0 ^= (w0 << 2);
		w0 ^= (w0 << 4);
		w0 ^= (w0 << 8);
		w0 ^= (w0 << 16);
		w0 ^= (w0 << 32);
		
		w0 &= M44; w1 ^= (w0 >>> 43);
		
		w1 ^= (w1 << 1);
		w1 ^= (w1 << 2);
		w1 ^= (w1 << 4);
		w1 ^= (w1 << 8);
		w1 ^= (w1 << 16);
		w1 ^= (w1 << 32);
		
		w1 &= M44; w2 ^= (w1 >>> 43);
		
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
		
		implCompactExt(zz);
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
		long l = u[j & 7] ^ (u[(j >>> 3) & 7] << 3) ^ (u[(j >>> 6) & 7] << 6);
		int k = 33;
		do
		{
			j  = (int)(x >>> k);
			g  = u[j & 7]
			   ^ u[(j >>> 3) & 7] << 3
			   ^ u[(j >>> 6) & 7] << 6
			   ^ u[(j >>> 9) & 7] << 9;
			l ^= (g <<   k);
			h ^= (g >>> -k);
		}
		while ((k -= 12) > 0);

		z[zOff    ] = l & M44;
		z[zOff + 1] = (l >>> 44) ^ (h << 20);
	}


	private static void implSquare( long[] x, long[] zz )
	{
		Nat.expand64To128( x[ 0 ], zz, 0 );
		Nat.expand64To128( x[ 1 ], zz, 2 );

		zz[ 4 ] = Nat.expand8to16( (int)x[ 2 ] ) & 0xFFFFFFFFL;
	}

}
