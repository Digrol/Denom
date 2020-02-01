package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Secp192k1 extends CustomFpCurve
{
	private static final int ARR_LEN = 6;

	// 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
	private static final int[] P = new int[] { 0xFFFFEE37, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExt = new int[] { 0x013C4FD1, 0x00002392, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFDC6E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExtInv = new int[] { 0xFEC3B02F, 0xFFFFDC6D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00002391, 0x00000002 };
	private static final int P5 = 0xFFFFFFFF;
	private static final int PExt11 = 0xFFFFFFFF;
	private static final int PInv33 = 0x11C9;


	public Secp192k1()
	{
		super( P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", // p
			ARR_LEN, false );
		
		super.init( new Element(), new Point( null, null, null ), "1.3.132.0.31",
			"00", // a
			"03", // b
			"FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", // order (n)
			"01", // cofactor (h)
			"04 DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"
			+ " 9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D" ); // G point

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

		/**
		 * return a sqrt root - the routine verifies that the calculation returns the right value - if
		 * none exists it returns null.
		 */
		public ECElement sqrt()
		{
			// Raise this element to the exponent 2^190 - 2^30 - 2^10 - 2^6 - 2^5 - 2^4 - 2^1 Breaking
			// up the exponent's binary representation into "repunits", we get: { 159 1s } { 1 0s } { 19
			// 1s } { 1 0s } { 3 1s } { 3 0s} { 3 1s } { 1 0s } Therefore we need an addition chain
			// containing 3, 19, 159 (the lengths of the repunits) We use: 1, 2, [3], 6, 8, 16, [19],
			// 35, 70, 140, [159]

			int[] x1 = this.arr;
			if( Nat.isZero( ARR_LEN, x1 ) || Nat.isOne( ARR_LEN, x1 ) )
			{
				return this;
			}

			int[] x2 = new int[ ARR_LEN ];
			elSquare( x1, x2 );
			elMultiply( x2, x1, x2 );
			int[] x3 = new int[ ARR_LEN ];
			elSquare( x2, x3 );
			elMultiply( x3, x1, x3 );
			int[] x6 = new int[ ARR_LEN ];
			elSquareN( x3, 3, x6 );
			elMultiply( x6, x3, x6 );
			int[] x8 = x6;
			elSquareN( x6, 2, x8 );
			elMultiply( x8, x2, x8 );
			int[] x16 = x2;
			elSquareN( x8, 8, x16 );
			elMultiply( x16, x8, x16 );
			int[] x19 = x8;
			elSquareN( x16, 3, x19 );
			elMultiply( x19, x3, x19 );
			int[] x35 = new int[ ARR_LEN ];
			elSquareN( x19, 16, x35 );
			elMultiply( x35, x16, x35 );
			int[] x70 = x16;
			elSquareN( x35, 35, x70 );
			elMultiply( x70, x35, x70 );
			int[] x140 = x35;
			elSquareN( x70, 70, x140 );
			elMultiply( x140, x70, x140 );
			int[] x159 = x70;
			elSquareN( x140, 19, x159 );
			elMultiply( x159, x19, x159 );

			int[] t1 = x159;
			elSquareN( t1, 20, t1 );
			elMultiply( t1, x19, t1 );
			elSquareN( t1, 4, t1 );
			elMultiply( t1, x3, t1 );
			elSquareN( t1, 6, t1 );
			elMultiply( t1, x3, t1 );
			elSquare( t1, t1 );

			int[] t2 = x3;
			elSquare( t1, t2 );

			return Arrays.equals( x1, t2 ) ? new Element( t1 ) : null;
		}
	}

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		long cc = Nat.mul33Add( ARR_LEN, PInv33, xx, 6, xx, 0, z, 0 );
		int c = Nat.mul33DWordAdd( ARR_LEN, PInv33, cc, z, 0 );

		if( c != 0 || (z[ 5 ] == P5 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( 6, PInv33, z );
		}
	}

	@Override
	protected void elReduceInt( int x, int[] z )
	{
		if( (x != 0 && Nat.mul33WordAdd( ARR_LEN, PInv33, x, z, 0 ) != 0) || (z[ 5 ] == P5 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		int c = Nat.add( ARR_LEN, x, y, z );
		if( c != 0 || (z[ 5 ] == P5 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elAddOne( int[] x, int[] z )
	{
		int c = Nat.inc( ARR_LEN, x, z );
		if( c != 0 || (z[ 5 ] == P5 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
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
			Nat.sub33From( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elTwice( int[] x, int[] z )
	{
		int c = Nat.shiftUpBit( 6, x, 0, z );
		if( c != 0 || (z[ 5 ] == P5 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( 6, PInv33, z );
		}
	}
}
