package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Secp224k1 extends CustomFpCurve
{
	private static final int ARR_LEN = 7;
	private static final int ARR_LEN2 = 14;

	// Calculated as ECConstants.TWO.modPow(Q.shiftRight(2), Q)
	private static final int[] PRECOMP_POW2 = new int[] { 0x33bfd202, 0xdcfad133, 0x2287624a, 0xc3811ba8, 0xa85558fc, 0x1eaef5d7, 0x8edf154c };

	// 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1
	private static final int[] P = { 0xFFFFE56D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExt = {
			0x02C23069, 0x00003526, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0xFFFFCADA, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExtInv = new int[] { 0xFD3DCF97, 0xFFFFCAD9, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00003525, 0x00000002 };
	private static final int P6 = 0xFFFFFFFF;
	private static final int PExt13 = 0xFFFFFFFF;
	private static final int PInv33 = 0x1A93;


	public Secp224k1()
	{
		super( P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D", // p
			ARR_LEN, false );
		
		super.init( new Element(), new CustomFpCurve.Point( null, null, null ), "1.3.132.0.32",
			"00", // a
			"05", // b
			"010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7", // order (n)
			"01", // cofactor (h)
			"04 A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"
			+ " 7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5" ); // G point
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

			this.arr = Nat.fromBigInteger( 224, X );
			if( (arr[ 6 ] == P6) && Nat.gte( ARR_LEN, arr, P ) )
			{
				Nat.add33To( ARR_LEN, PInv33, arr );
			}
		}

		private Element( int[] x )
		{
			this.arr = x;
		}

		@Override
		public ECElement create( BigInteger x )
		{
			return new Element( x );
		}

		@Override
		protected ECElement create( int[] x )
		{
			return new Element( x );
		}


		// D.1.4 91
		/**
		 * return a sqrt root - the routine verifies that the calculation returns the right value - if
		 * none exists it returns null.
		 */
		@Override
		public ECElement sqrt()
		{
			// Q == 8m + 5, so we use Pocklington's method for this case. First, raise this element to
			// the exponent 2^221 - 2^29 - 2^9 - 2^8 - 2^6 - 2^4 - 2^1 (i.e. m + 1)
			// Breaking up the exponent's binary representation into "repunits", we get:
			// { 191 1s } { 1 0s } { 19 1s } { 2 0s } { 1 1s } { 1 0s} { 1 1s } { 1 0s} { 3 1s } { 1 0s}
			// Therefore we need an addition chain containing 1, 3, 19, 191 (the lengths of the repunits)
			// We use: [1], 2, [3], 4, 8, 11, [19], 23, 42, 84, 107, [191]

			int[] x1 = this.arr;
			if( Nat.isZero( ARR_LEN, x1 ) || Nat.isOne( ARR_LEN, x1 ) )
			{
				return this;
			}

			int[] x2 = new int[ ARR_LEN ];
			elSquare( x1, x2 );
			elMultiply( x2, x1, x2 );
			int[] x3 = x2;
			elSquare( x2, x3 );
			elMultiply( x3, x1, x3 );
			int[] x4 = new int[ ARR_LEN ];
			elSquare( x3, x4 );
			elMultiply( x4, x1, x4 );
			int[] x8 = new int[ ARR_LEN ];
			elSquareN( x4, 4, x8 );
			elMultiply( x8, x4, x8 );
			int[] x11 = new int[ ARR_LEN ];
			elSquareN( x8, 3, x11 );
			elMultiply( x11, x3, x11 );
			int[] x19 = x11;
			elSquareN( x11, 8, x19 );
			elMultiply( x19, x8, x19 );
			int[] x23 = x8;
			elSquareN( x19, 4, x23 );
			elMultiply( x23, x4, x23 );
			int[] x42 = x4;
			elSquareN( x23, 19, x42 );
			elMultiply( x42, x19, x42 );
			int[] x84 = new int[ ARR_LEN ];
			elSquareN( x42, 42, x84 );
			elMultiply( x84, x42, x84 );
			int[] x107 = x42;
			elSquareN( x84, 23, x107 );
			elMultiply( x107, x23, x107 );
			int[] x191 = x23;
			elSquareN( x107, 84, x191 );
			elMultiply( x191, x84, x191 );

			int[] t1 = x191;
			elSquareN( t1, 20, t1 );
			elMultiply( t1, x19, t1 );
			elSquareN( t1, 3, t1 );
			elMultiply( t1, x1, t1 );
			elSquareN( t1, 2, t1 );
			elMultiply( t1, x1, t1 );
			elSquareN( t1, 4, t1 );
			elMultiply( t1, x3, t1 );
			elSquare( t1, t1 );

			int[] t2 = x84;
			elSquare( t1, t2 );

			if( Arrays.equals( x1, t2 ) )
			{
				return new Element( t1 );
			}

			// If the first guess is incorrect, we multiply by a precomputed power of 2 to get the
			// second guess, which is ((4x)^(m + 1))/2 mod Q
			elMultiply( t1, PRECOMP_POW2, t1 );
			elSquare( t1, t2 );

			if( Arrays.equals( x1, t2 ) )
			{
				return new Element( t1 );
			}

			return null;
		}

	} // Element

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		long cc = Nat.mul33Add( ARR_LEN, PInv33, xx, 7, xx, 0, z, 0 );
		int c = Nat.mul33DWordAdd( ARR_LEN, PInv33, cc, z, 0 );

		if( c != 0 || (z[ 6 ] == P6 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elReduceInt( int x, int[] z )
	{
		if( ((x != 0) && Nat.mul33WordAdd( ARR_LEN, PInv33, x, z, 0 ) != 0) || (z[ 6 ] == P6 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		int c = Nat.add( ARR_LEN, x, y, z );
		if( c != 0 || (z[ 6 ] == P6 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elMultiplyAddToExt( int[] x, int[] y, int[] zz )
	{
		int c = Nat.mulAddTo( ARR_LEN, x, y, zz );
		if( c != 0 || (zz[ 13 ] == PExt13 && Nat.gte( ARR_LEN2, zz, PExt )) )
		{
			if( Nat.addTo( PExtInv.length, PExtInv, zz ) != 0 )
			{
				Nat.incAt( 14, zz, PExtInv.length );
			}
		}
	}

	@Override
	protected void elSubtract( int[] x, int[] y, int[] z )
	{
		int c = Nat.sub( ARR_LEN, x, y, z );
		if( c != 0 )
		{
			Nat.sub33From( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elTwice( int[] x, int[] z )
	{
		int c = Nat.shiftUpBit( ARR_LEN, x, 0, z );
		if( c != 0 || (z[ 6 ] == P6 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

}
