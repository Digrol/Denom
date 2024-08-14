package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

// P-192
public class Secp192r1 extends CustomFpCurve
{
	private static final int ARR_LEN = 6;

	private static final long M = 0xFFFFFFFFL;

	// 2^192 - 2^64 - 1
	private static final int[] P = new int[] { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExt = new int[] { 0x00000001, 0x00000000, 0x00000002, 0x00000000, 0x00000001, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExtInv = new int[] { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000002 };
	private static final int P5 = 0xFFFFFFFF;
	private static final int PExt11 = 0xFFFFFFFF;


	public Secp192r1()
	{
		super( P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", // p
			ARR_LEN, false );
		
		super.init( new Element(), new Point( null, null, null ), "1.2.840.10045.3.1.1",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", // a
			"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", // b
			"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", // order (n)
			"01", // cofactor (h)
			"04 188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
			+ " 07192B95FFC8DA78631011ED6B24CDD573F977A11E794811" ); // G point
	}

	// =================================================================================================================
	// ELEMENT
	// =================================================================================================================

	private class Element extends CustomFpCurve.Element
	{
		private Element() {}

		private Element( BigInteger X )
		{
			MUST( (X != null) && (X.signum() >= 0) && (X.compareTo( getP() ) < 0) );

			this.arr = Nat.fromBigInteger( 192, X );
			if( arr[ 5 ] == P5 && Nat.gte( ARR_LEN, arr, P ) )
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

		// D.1.4 91
		/**
		 * return a sqrt root - the routine verifies that the calculation returns the right value - if
		 * none exists it returns null.
		 */
		public ECElement sqrt()
		{
			// Raise this element to the exponent 2^190 - 2^62

			int[] x1 = this.arr;
			if( Nat.isZero( ARR_LEN, x1 ) || Nat.isOne( ARR_LEN, x1 ) )
			{
				return this;
			}

			int[] t1 = new int[ ARR_LEN ];
			int[] t2 = new int[ ARR_LEN ];

			elSquare( x1, t1 );
			elMultiply( t1, x1, t1 );

			elSquareN( t1, 2, t2 );
			elMultiply( t2, t1, t2 );

			elSquareN( t2, 4, t1 );
			elMultiply( t1, t2, t1 );

			elSquareN( t1, 8, t2 );
			elMultiply( t2, t1, t2 );

			elSquareN( t2, 16, t1 );
			elMultiply( t1, t2, t1 );

			elSquareN( t1, 32, t2 );
			elMultiply( t2, t1, t2 );

			elSquareN( t2, 64, t1 );
			elMultiply( t1, t2, t1 );

			elSquareN( t1, 62, t1 );
			elSquare( t1, t2 );

			return Arrays.equals( x1, t2 ) ? new Element( t1 ) : null;
		}
	}

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		long xx06 = xx[ 6 ] & M, xx07 = xx[ 7 ] & M, xx08 = xx[ 8 ] & M;
		long xx09 = xx[ 9 ] & M, xx10 = xx[ 10 ] & M, xx11 = xx[ 11 ] & M;

		long t0 = xx06 + xx10;
		long t1 = xx07 + xx11;

		long cc = 0;
		cc += (xx[ 0 ] & M) + t0;
		int z0 = (int)cc;
		cc >>= 32;
		cc += (xx[ 1 ] & M) + t1;
		z[ 1 ] = (int)cc;
		cc >>= 32;

		t0 += xx08;
		t1 += xx09;

		cc += (xx[ 2 ] & M) + t0;
		long z2 = cc & M;
		cc >>= 32;
		cc += (xx[ 3 ] & M) + t1;
		z[ 3 ] = (int)cc;
		cc >>= 32;

		t0 -= xx06;
		t1 -= xx07;

		cc += (xx[ 4 ] & M) + t0;
		z[ 4 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 5 ] & M) + t1;
		z[ 5 ] = (int)cc;
		cc >>= 32;

		z2 += cc;

		cc += (z0 & M);
		z[ 0 ] = (int)cc;
		cc >>= 32;
		if( cc != 0 )
		{
			cc += (z[ 1 ] & M);
			z[ 1 ] = (int)cc;
			z2 += cc >> 32;
		}
		z[ 2 ] = (int)z2;
		cc = z2 >> 32;

		if( (cc != 0 && Nat.incAt( 6, z, 3 ) != 0) || (z[ 5 ] == P5 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	@Override
	protected void elReduceInt( int x, int[] z )
	{
		long cc = 0;

		if( x != 0 )
		{
			long xx06 = x & M;

			cc += (z[ 0 ] & M) + xx06;
			z[ 0 ] = (int)cc;
			cc >>= 32;
			if( cc != 0 )
			{
				cc += (z[ 1 ] & M);
				z[ 1 ] = (int)cc;
				cc >>= 32;
			}
			cc += (z[ 2 ] & M) + xx06;
			z[ 2 ] = (int)cc;
			cc >>= 32;
		}

		if( (cc != 0 && Nat.incAt( 6, z, 3 ) != 0) || (z[ 5 ] == P5 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		int c = Nat.add( ARR_LEN, x, y, z );
		if( c != 0 || (z[ 5 ] == P5 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	@Override
	protected void elAddOne( int[] x, int[] z )
	{
		int c = Nat.inc( ARR_LEN, x, z );
		if( c != 0 || (z[ 5 ] == P5 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}


	@Override
	protected void elMultiplyAddToExt( int[] x, int[] y, int[] zz )
	{
		int c = Nat.mulAddTo( ARR_LEN, x, y, zz );
		if( c != 0 || (zz[ 11 ] == PExt11 && Nat.gte( 12, zz, PExt )) )
		{
			if( Nat.addTo( PExtInv.length, PExtInv, zz ) != 0 )
			{
				Nat.incAt( 12, zz, PExtInv.length );
			}
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
		int c = Nat.shiftUpBit( 6, x, 0, z );
		if( c != 0 || (z[ 5 ] == P5 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	private void addPInvTo( int[] z )
	{
		long c = (z[ 0 ] & M) + 1;
		z[ 0 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			c += (z[ 1 ] & M);
			z[ 1 ] = (int)c;
			c >>= 32;
		}
		c += (z[ 2 ] & M) + 1;
		z[ 2 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			Nat.incAt( 6, z, 3 );
		}
	}

	private void subPInvFrom( int[] z )
	{
		long c = (z[ 0 ] & M) - 1;
		z[ 0 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			c += (z[ 1 ] & M);
			z[ 1 ] = (int)c;
			c >>= 32;
		}
		c += (z[ 2 ] & M) - 1;
		z[ 2 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			Nat.decAt( 6, z, 3 );
		}
	}

}
