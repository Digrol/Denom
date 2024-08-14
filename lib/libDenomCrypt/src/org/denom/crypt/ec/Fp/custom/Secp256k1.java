package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Secp256k1 extends CustomFpCurve
{
	private static final int ARR_LEN = 8;
	private static final int ARR_LEN2 = 16;

	// 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
	private static final int[] P = new int[] { 0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExt = new int[] { 0x000E90A1, 0x000007A2, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFF85E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExtInv = new int[] { 0xFFF16F5F, 0xFFFFF85D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x000007A1, 0x00000002 };
	private static final int P7 = 0xFFFFFFFF;
	private static final int PExt15 = 0xFFFFFFFF;
	private static final int PInv33 = 0x3D1;


	public Secp256k1()
	{
		super( P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", // p
			ARR_LEN, false );
		
		super.init( new Element(), new Point( null, null, null ), "1.3.132.0.10",
			"00", // a
			"07", // b
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", // order (n)
			"01", // cofactor (h)
			"04 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
			+ " 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8" ); // G point
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

			this.arr = Nat.fromBigInteger( 256, X );
			if( arr[ 7 ] == P7 && Nat.gte( ARR_LEN, arr, P ) )
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
			// Raise this element to the exponent 2^254 - 2^30 - 2^7 - 2^6 - 2^5 - 2^4 - 2^2 Breaking up
			// the exponent's binary representation into "repunits", we get: { 223 1s } { 1 0s } { 22 1s }
			// { 4 0s } { 2 1s } { 2 0s} Therefore we need an addition chain containing 2, 22, 223
			// (the lengths of the repunits) We use: 1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]

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
			int[] x9 = x6;
			elSquareN( x6, 3, x9 );
			elMultiply( x9, x3, x9 );
			int[] x11 = x9;
			elSquareN( x9, 2, x11 );
			elMultiply( x11, x2, x11 );
			int[] x22 = new int[ ARR_LEN ];
			elSquareN( x11, 11, x22 );
			elMultiply( x22, x11, x22 );
			int[] x44 = x11;
			elSquareN( x22, 22, x44 );
			elMultiply( x44, x22, x44 );
			int[] x88 = new int[ ARR_LEN ];
			elSquareN( x44, 44, x88 );
			elMultiply( x88, x44, x88 );
			int[] x176 = new int[ ARR_LEN ];
			elSquareN( x88, 88, x176 );
			elMultiply( x176, x88, x176 );
			int[] x220 = x88;
			elSquareN( x176, 44, x220 );
			elMultiply( x220, x44, x220 );
			int[] x223 = x44;
			elSquareN( x220, 3, x223 );
			elMultiply( x223, x3, x223 );

			int[] t1 = x223;
			elSquareN( t1, 23, t1 );
			elMultiply( t1, x22, t1 );
			elSquareN( t1, 6, t1 );
			elMultiply( t1, x2, t1 );
			elSquareN( t1, 2, t1 );

			int[] t2 = x2;
			elSquare( t1, t2 );

			return Arrays.equals( x1, t2 ) ? new Element( t1 ) : null;
		}

	}

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		long cc = Nat.mul33Add( ARR_LEN, PInv33, xx, 8, xx, 0, z, 0 );
		int c = Nat.mul33DWordAdd( ARR_LEN, PInv33, cc, z, 0 );

		if( c != 0 || (z[ 7 ] == P7 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elReduceInt( int x, int[] z )
	{
		if( (x != 0 && Nat.mul33WordAdd( ARR_LEN, PInv33, x, z, 0 ) != 0) || (z[ 7 ] == P7 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		int c = Nat.add( ARR_LEN, x, y, z );
		if( c != 0 || (z[ 7 ] == P7 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( 8, PInv33, z );
		}
	}

	@Override
	protected void elAddOne( int[] x, int[] z )
	{
		int c = Nat.inc( ARR_LEN, x, z );
		if( c != 0 || (z[ 7 ] == P7 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elMultiplyAddToExt( int[] x, int[] y, int[] zz )
	{
		int c = Nat.mulAddTo( ARR_LEN, x, y, zz );
		if( c != 0 || (zz[ 15 ] == PExt15 && Nat.gte( ARR_LEN2, zz, PExt )) )
		{
			if( Nat.addTo( PExtInv.length, PExtInv, zz ) != 0 )
			{
				Nat.incAt( ARR_LEN2, zz, PExtInv.length );
			}
		}
	}

	@Override
	protected void elSubtract( int[] x, int[] y, int[] z )
	{
		int c = Nat.sub( ARR_LEN, x, y, z );
		if( c != 0 )
		{
			Nat.sub33From( 8, PInv33, z );
		}
	}

	@Override
	protected void elTwice( int[] x, int[] z )
	{
		int c = Nat.shiftUpBit( ARR_LEN, x, 0, z );
		if( c != 0 || (z[ 7 ] == P7 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

}
