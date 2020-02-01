package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

// P-384
public class Secp384r1 extends CustomFpCurve
{
	private static final int ARR_LEN = 12;
	private static final int ARR_LEN2 = 24;

	private static final long M = 0xFFFFFFFFL;

	// 2^384 - 2^128 - 2^96 + 2^32 - 1
	private static final int[] P = new int[] { 0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExt = new int[] { 0x00000001, 0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000000, 0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFE, 0x00000001, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExtInv = new int[] { 0xFFFFFFFF, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000001, 0x00000002 };
	private static final int P11 = 0xFFFFFFFF;
	private static final int PExt23 = 0xFFFFFFFF;


	public Secp384r1()
	{
		super( P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", // p
			ARR_LEN, false );
		
		super.init( new Element(), new Point( null, null, null ), "1.3.132.0.34",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", // a
			"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", // b
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", // order (n)
			"01", // cofactor (h)
			"04 AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
			+ " 3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F" ); // G point
	}

	// =================================================================================================================
	// ELEMENT
	// =================================================================================================================

	private class Element extends CustomFpCurve.Element
	{
		private Element() {}

		private Element( BigInteger X )
		{
			MUST( X != null && (X.signum() >= 0) && (X.compareTo( getP() ) < 0) );

			this.arr = Nat.fromBigInteger( 384, X );
			if( arr[ 11 ] == P11 && Nat.gte( ARR_LEN, arr, P ) )
			{
				Nat.subFrom( ARR_LEN, P, arr );
			}
		}

		private Element( int[] x )
		{
			this.arr = x;
		}


		@Override
		protected ECElement create( int[] x )
		{
			return new Element( x );
		}

		@Override
		public ECElement create( BigInteger x )
		{
			return new Element( x );
		}

		/**
		 * return a sqrt root - the routine verifies that the calculation returns the right value - if
		 * none exists it returns null.
		 */
		public ECElement sqrt()
		{
			// Raise this element to the exponent 2^382 - 2^126 - 2^94 + 2^30

			int[] x1 = this.arr;
			if( Nat.isZero( ARR_LEN, x1 ) || Nat.isOne( ARR_LEN, x1 ) )
			{
				return this;
			}

			int[] t1 = new int[ ARR_LEN ];
			int[] t2 = new int[ ARR_LEN ];
			int[] t3 = new int[ ARR_LEN ];
			int[] t4 = new int[ ARR_LEN ];

			elSquare( x1, t1 );
			elMultiply( t1, x1, t1 );

			elSquareN( t1, 2, t2 );
			elMultiply( t2, t1, t2 );

			elSquare( t2, t2 );
			elMultiply( t2, x1, t2 );

			elSquareN( t2, 5, t3 );
			elMultiply( t3, t2, t3 );

			elSquareN( t3, 5, t4 );
			elMultiply( t4, t2, t4 );

			elSquareN( t4, 15, t2 );
			elMultiply( t2, t4, t2 );

			elSquareN( t2, 2, t3 );
			elMultiply( t1, t3, t1 );

			elSquareN( t3, 28, t3 );
			elMultiply( t2, t3, t2 );

			elSquareN( t2, 60, t3 );
			elMultiply( t3, t2, t3 );

			int[] r = t2;

			elSquareN( t3, 120, r );
			elMultiply( r, t3, r );

			elSquareN( r, 15, r );
			elMultiply( r, t4, r );

			elSquareN( r, 33, r );
			elMultiply( r, t1, r );

			elSquareN( r, 64, r );
			elMultiply( r, x1, r );

			elSquareN( r, 30, t1 );
			elSquare( t1, t2 );

			return Arrays.equals( x1, t2 ) ? new Element( t1 ) : null;
		}
	}

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		long xx16 = xx[ 16 ] & M, xx17 = xx[ 17 ] & M, xx18 = xx[ 18 ] & M, xx19 = xx[ 19 ] & M;
		long xx20 = xx[ 20 ] & M, xx21 = xx[ 21 ] & M, xx22 = xx[ 22 ] & M, xx23 = xx[ 23 ] & M;

		final long n = 1;

		long t0 = (xx[ 12 ] & M) + xx20 - n;
		long t1 = (xx[ 13 ] & M) + xx22;
		long t2 = (xx[ 14 ] & M) + xx22 + xx23;
		long t3 = (xx[ 15 ] & M) + xx23;
		long t4 = xx17 + xx21;
		long t5 = xx21 - xx23;
		long t6 = xx22 - xx23;
		long t7 = t0 + t5;

		long cc = 0;
		cc += (xx[ 0 ] & M) + t7;
		z[ 0 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 1 ] & M) + xx23 - t0 + t1;
		z[ 1 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 2 ] & M) - xx21 - t1 + t2;
		z[ 2 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 3 ] & M) - t2 + t3 + t7;
		z[ 3 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 4 ] & M) + xx16 + xx21 + t1 - t3 + t7;
		z[ 4 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 5 ] & M) - xx16 + t1 + t2 + t4;
		z[ 5 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 6 ] & M) + xx18 - xx17 + t2 + t3;
		z[ 6 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 7 ] & M) + xx16 + xx19 - xx18 + t3;
		z[ 7 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 8 ] & M) + xx16 + xx17 + xx20 - xx19;
		z[ 8 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 9 ] & M) + xx18 - xx20 + t4;
		z[ 9 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 10 ] & M) + xx18 + xx19 - t5 + t6;
		z[ 10 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 11 ] & M) + xx19 + xx20 - t6;
		z[ 11 ] = (int)cc;
		cc >>= 32;
		cc += n;

		elReduceInt( (int)cc, z );
	}

	@Override
	protected void elReduceInt( int x, int[] z )
	{
		long cc = 0;

		if( x != 0 )
		{
			long xx12 = x & M;

			cc += (z[ 0 ] & M) + xx12;
			z[ 0 ] = (int)cc;
			cc >>= 32;
			cc += (z[ 1 ] & M) - xx12;
			z[ 1 ] = (int)cc;
			cc >>= 32;
			if( cc != 0 )
			{
				cc += (z[ 2 ] & M);
				z[ 2 ] = (int)cc;
				cc >>= 32;
			}
			cc += (z[ 3 ] & M) + xx12;
			z[ 3 ] = (int)cc;
			cc >>= 32;
			cc += (z[ 4 ] & M) + xx12;
			z[ 4 ] = (int)cc;
			cc >>= 32;
		}

		if( (cc != 0 && Nat.incAt( 12, z, 5 ) != 0) || (z[ 11 ] == P11 && Nat.gte( 12, z, P )) )
		{
			addPInvTo( z );
		}
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		int c = Nat.add( ARR_LEN, x, y, z );
		if( c != 0 || (z[ 11 ] == P11 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	@Override
	protected void elMultiplyAddToExt( int[] x, int[] y, int[] zz )
	{
		int c = Nat.mulAddTo( ARR_LEN, x, y, zz );
		if( c != 0 || (zz[ 23 ] == PExt23 && Nat.gte( ARR_LEN2, zz, PExt )) )
		{
			if( Nat.addTo( PExtInv.length, PExtInv, zz ) != 0 )
			{
				Nat.incAt( ARR_LEN2, zz, PExtInv.length );
			}
		}
	}
	
	@Override
	protected void elAddOne( int[] x, int[] z )
	{
		int c = Nat.inc( ARR_LEN, x, z );
		if( c != 0 || (z[ 11 ] == P11 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	@Override
	protected void elSubtract( int[] x, int[] y, int[] z )
	{
		int c = Nat.sub( ARR_LEN, x, y, z );
		if( c != 0 )
		{
			subPInvFrom( z );
		}
	}

	@Override
	protected void elTwice( int[] x, int[] z )
	{
		int c = Nat.shiftUpBit( ARR_LEN, x, 0, z );
		if( c != 0 || (z[ 11 ] == P11 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	private static void addPInvTo( int[] z )
	{
		long c = (z[ 0 ] & M) + 1;
		z[ 0 ] = (int)c;
		c >>= 32;
		c += (z[ 1 ] & M) - 1;
		z[ 1 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			c += (z[ 2 ] & M);
			z[ 2 ] = (int)c;
			c >>= 32;
		}
		c += (z[ 3 ] & M) + 1;
		z[ 3 ] = (int)c;
		c >>= 32;
		c += (z[ 4 ] & M) + 1;
		z[ 4 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			Nat.incAt( 12, z, 5 );
		}
	}

	private static void subPInvFrom( int[] z )
	{
		long c = (z[ 0 ] & M) - 1;
		z[ 0 ] = (int)c;
		c >>= 32;
		c += (z[ 1 ] & M) + 1;
		z[ 1 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			c += (z[ 2 ] & M);
			z[ 2 ] = (int)c;
			c >>= 32;
		}
		c += (z[ 3 ] & M) - 1;
		z[ 3 ] = (int)c;
		c >>= 32;
		c += (z[ 4 ] & M) - 1;
		z[ 4 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			Nat.decAt( 12, z, 5 );
		}
	}
}
