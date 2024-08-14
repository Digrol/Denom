package org.denom.crypt.ec.F2m.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Sect193 extends CustomF2mCurve
{
	private static final int ARR_LEN = 4;
	private static final int ARR_LEN2 = 8;

	private static final long M01 = 1L;
	private static final long M49 = -1L >>> 15;


	public static Sect193 r1()
	{
		return new Sect193( "1.3.132.0.24",
			"0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01", // a
			"00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814", // b
			"01000000000000000000000000C7F34A778F443ACC920EBA49", // n
			"02", // h
			"04 01F481BC5F0FF84A74AD6CDF6FDEF4BF6179625372D8C0C5E1"
			+ " 0025E399F2903712CCF3EA9E3A1AD17FB0B3201B6AF7CE1B05", // G point
			false );
	}


	public static Sect193 r2()
	{
		return new Sect193( "1.3.132.0.25",
			"0163F35A5137C2CE3EA6ED8667190B0BC43ECD69977702709B", // a
			"00C9BB9E8927D4D64C377E2AB2856A5B16E3EFB7F61D4316AE", // b
			"010000000000000000000000015AAB561B005413CCD4EE99D5", // n
			"02", // h
			"04 00D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F"
			+ " 01CE94335607C304AC29E7DEFBD9CA01F596F927224CDECF6C", // G point
			false );
	}


	private Sect193( String oid, String aHex, String bHex, String orderHex, String cofactorHex, String gPointHex, boolean isKoblitz )
	{
		super( 193, 15, 0, 0, ARR_LEN, isKoblitz );
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

			long t = arr[ 3 ] >>> 1;
			arr[ 0 ] ^= t ^ (t << 15);
			arr[ 1 ] ^= (t >>> 49);
			arr[ 3 ] &= M01;
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
			Sect193.multiply( arr, ((Element)b).arr, z );
			return new Element( z );
		}

		public ECElement multiplyPlusProduct( ECElement b, ECElement x, ECElement y )
		{
			long[] ax = this.arr, bx = ((Element)b).arr;
			long[] xx = ((Element)x).arr, yx = ((Element)y).arr;

			long[] tt = new long[ ARR_LEN2 ];
			Sect193.multiplyAddToExt( ax, bx, tt );
			Sect193.multiplyAddToExt( xx, yx, tt );

			long[] z = new long[ ARR_LEN ];
			Sect193.reduce( tt, z );
			return new Element( z );
		}

		public ECElement square()
		{
			long[] z = new long[ ARR_LEN ];
			Sect193.square( arr, z );
			return new Element( z );
		}

		public ECElement squarePlusProduct( ECElement x, ECElement y )
		{
			long[] ax = this.arr;
			long[] xx = ((Element)x).arr, yx = ((Element)y).arr;

			long[] tt = new long[ ARR_LEN2 ];
			Sect193.squareAddToExt( ax, tt );
			Sect193.multiplyAddToExt( xx, yx, tt );

			long[] z = new long[ ARR_LEN ];
			Sect193.reduce( tt, z );
			return new Element( z );
		}

		public ECElement squarePow( int pow )
		{
			if( pow < 1 )
			{
				return this;
			}

			long[] z = new long[ ARR_LEN ];
			Sect193.squareN( arr, pow, z );
			return new Element( z );
		}

		public int trace()
		{
			return (int)(arr[ 0 ]) & 1;
		}

		public ECElement invert()
		{
			long[] z = new long[ ARR_LEN ];
			Sect193.invert( arr, z );
			return new Element( z );
		}

		public ECElement sqrt()
		{
			long[] z = new long[ ARR_LEN ];
			Sect193.sqrt( arr, z );
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
			return 1930015 ^ java.util.Arrays.hashCode( arr );
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

		// 3 | 192
		squareN( t0, 1, t1 );
		multiply( t0, t1, t0 );
		squareN( t1, 1, t1 );
		multiply( t0, t1, t0 );

		// 2 | 64
		squareN( t0, 3, t1 );
		multiply( t0, t1, t0 );

		// 2 | 32
		squareN( t0, 6, t1 );
		multiply( t0, t1, t0 );

		// 2 | 16
		squareN( t0, 12, t1 );
		multiply( t0, t1, t0 );

		// 2 | 8
		squareN( t0, 24, t1 );
		multiply( t0, t1, t0 );

		// 2 | 4
		squareN( t0, 48, t1 );
		multiply( t0, t1, t0 );

		// 2 | 2
		squareN( t0, 96, t1 );
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
		long x0 = xx[ 0 ], x1 = xx[ 1 ], x2 = xx[ 2 ], x3 = xx[ 3 ], x4 = xx[ 4 ], x5 = xx[ 5 ], x6 = xx[ 6 ];

		x2 ^= (x6 << 63);
		x3 ^= (x6 >>> 1) ^ (x6 << 14);
		x4 ^= (x6 >>> 50);

		x1 ^= (x5 << 63);
		x2 ^= (x5 >>> 1) ^ (x5 << 14);
		x3 ^= (x5 >>> 50);

		x0 ^= (x4 << 63);
		x1 ^= (x4 >>> 1) ^ (x4 << 14);
		x2 ^= (x4 >>> 50);

		long t = x3 >>> 1;
		z[ 0 ] = x0 ^ t ^ (t << 15);
		z[ 1 ] = x1 ^ (t >>> 49);
		z[ 2 ] = x2;
		z[ 3 ] = x3 & M01;
	}


	private static void sqrt( long[] x, long[] z )
	{
		long u0, u1;
		u0 = Nat.unshuffle( x[ 0 ] );
		u1 = Nat.unshuffle( x[ 1 ] );
		long e0 = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
		long c0 = (u0 >>> 32) | (u1 & 0xFFFFFFFF00000000L);

		u0 = Nat.unshuffle( x[ 2 ] );
		long e1 = (u0 & 0x00000000FFFFFFFFL) ^ (x[ 3 ] << 32);
		long c1 = (u0 >>> 32);

		z[ 0 ] = e0 ^ (c0 << 8);
		z[ 1 ] = e1 ^ (c1 << 8) ^ (c0 >>> 56) ^ (c0 << 33);
		z[ 2 ] = (c1 >>> 56) ^ (c1 << 33) ^ (c0 >>> 31);
		z[ 3 ] = (c1 >>> 31);
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
		zz[ 0 ] = z0 ^ (z1 << 49);
		zz[ 1 ] = (z1 >>> 15) ^ (z2 << 34);
		zz[ 2 ] = (z2 >>> 30) ^ (z3 << 19);
		zz[ 3 ] = (z3 >>> 45) ^ (z4 << 4) ^ (z5 << 53);
		zz[ 4 ] = (z4 >>> 60) ^ (z6 << 38) ^ (z5 >>> 11);
		zz[ 5 ] = (z6 >>> 26) ^ (z7 << 23);
		zz[ 6 ] = (z7 >>> 41);
		zz[ 7 ] = 0;
	}


	private static void implExpand( long[] x, long[] z )
	{
		long x0 = x[ 0 ], x1 = x[ 1 ], x2 = x[ 2 ], x3 = x[ 3 ];
		z[ 0 ] = x0 & M49;
		z[ 1 ] = ((x0 >>> 49) ^ (x1 << 15)) & M49;
		z[ 2 ] = ((x1 >>> 34) ^ (x2 << 30)) & M49;
		z[ 3 ] = ((x2 >>> 19) ^ (x3 << 45));
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
		int k = 36;
		do
		{
			j  = (int)(x >>> k);
			g  = u[j & 7]
			   ^ u[(j >>> 3) & 7] << 3
			   ^ u[(j >>> 6) & 7] << 6
			   ^ u[(j >>> 9) & 7] << 9
			   ^ u[(j >>> 12) & 7] << 12;
			l ^= (g <<   k);
			h ^= (g >>> -k);
		}
		while( (k -= 15) > 0 );

		z[ zOff ] ^= l & M49;
		z[ zOff + 1 ] ^= (l >>> 49) ^ (h << 15);
	}


	private static void implSquare( long[] x, long[] zz )
	{
		Nat.expand64To128( x[ 0 ], zz, 0 );
		Nat.expand64To128( x[ 1 ], zz, 2 );
		Nat.expand64To128( x[ 2 ], zz, 4 );
		zz[ 6 ] = (x[ 3 ] & M01);
	}

}
