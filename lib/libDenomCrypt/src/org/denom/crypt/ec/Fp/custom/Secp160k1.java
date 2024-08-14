package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Secp160k1 extends CustomFpCurve
{
	private static final int ARR_LEN = 5;
	private static final int ARR_LEN2 = 10;

	// 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
	private static final int[] P = new int[] { 0xFFFFAC73, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExt = new int[] { 0x1B44BBA9, 0x0000A71A, 0x00000001, 0x00000000, 0x00000000, 0xFFFF58E6, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExtInv = new int[] { 0xE4BB4457, 0xFFFF58E5, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x0000A719, 0x00000002 };
	private static final int P4 = 0xFFFFFFFF;
	private static final int PExt9 = 0xFFFFFFFF;
	private static final int PInv33 = 0x538D;


	public Secp160k1()
	{
		super( P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", // p
			ARR_LEN, false );
		
		super.init( new Element(), new Point( null, null, null ), "1.3.132.0.9",
			"00", // a
			"07", // b
			"0100000000000000000001B8FA16DFAB9ACA16B6B3", // order (n)
			"01", // cofactor (h)
			"04 3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"
			+ " 938CF935318FDCED6BC28286531733C3F03C4FEE" ); // G point
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

			this.arr = Nat.fromBigInteger( 160, X );
			if( (arr[ 4 ] == P4) && Nat.gte( ARR_LEN, arr, P ) )
			{
				Nat.subFrom( ARR_LEN, P, arr );
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
		public ECElement sqrt()
		{
			// Raise this element to the exponent 2^158 - 2^30 - 2^12 - 2^10 - 2^7 - 2^6 - 2^5 - 2^1 -
			// 2^0 Breaking up the exponent's binary representation into "repunits", we get: { 127 1s }
			// { 1 0s } { 17 1s } { 1 0s } { 1 1s } { 1 0s } { 2 1s } { 3 0s } { 3 1s } { 1 0s } { 1 1s
			// } Therefore we need an addition chain containing 1, 2, 3, 17, 127 (the lengths of the
			// repunits) We use: [1], [2], [3], 4, 7, 14, [17], 31, 62, 124, [127]

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
			int[] x4 = new int[ ARR_LEN ];
			elSquare( x3, x4 );
			elMultiply( x4, x1, x4 );
			int[] x7 = new int[ ARR_LEN ];
			elSquareN( x4, 3, x7 );
			elMultiply( x7, x3, x7 );
			int[] x14 = x4;
			elSquareN( x7, 7, x14 );
			elMultiply( x14, x7, x14 );
			int[] x17 = x7;
			elSquareN( x14, 3, x17 );
			elMultiply( x17, x3, x17 );
			int[] x31 = new int[ ARR_LEN ];
			elSquareN( x17, 14, x31 );
			elMultiply( x31, x14, x31 );
			int[] x62 = x14;
			elSquareN( x31, 31, x62 );
			elMultiply( x62, x31, x62 );
			int[] x124 = x31;
			elSquareN( x62, 62, x124 );
			elMultiply( x124, x62, x124 );
			int[] x127 = x62;
			elSquareN( x124, 3, x127 );
			elMultiply( x127, x3, x127 );

			int[] t1 = x127;
			elSquareN( t1, 18, t1 );
			elMultiply( t1, x17, t1 );
			elSquareN( t1, 2, t1 );
			elMultiply( t1, x1, t1 );
			elSquareN( t1, 3, t1 );
			elMultiply( t1, x2, t1 );
			elSquareN( t1, 6, t1 );
			elMultiply( t1, x3, t1 );
			elSquareN( t1, 2, t1 );
			elMultiply( t1, x1, t1 );

			int[] t2 = x2;
			elSquare( t1, t2 );

			return Arrays.equals( x1, t2 ) ? new Element( t1 ) : null;
		}
	}

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		long cc = Nat.mul33Add( ARR_LEN, PInv33, xx, 5, xx, 0, z, 0 );
		int c = Nat.mul33DWordAdd( ARR_LEN, PInv33, cc, z, 0 );

		if( c != 0 || (z[ 4 ] == P4 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elReduceInt( int x, int[] z )
	{
		if( (x != 0 && Nat.mul33WordAdd( ARR_LEN, PInv33, x, z, 0 ) != 0) || (z[ 4 ] == P4 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		int c = Nat.add( ARR_LEN, x, y, z );
		if( c != 0 || (z[ 4 ] == P4 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elAddOne( int[] x, int[] z )
	{
		int c = Nat.inc( ARR_LEN, x, z );
		if( c != 0 || (z[ 4 ] == P4 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elMultiplyAddToExt( int[] x, int[] y, int[] zz )
	{
		int c = Nat.mulAddTo( ARR_LEN, x, y, zz );
		if( c != 0 || (zz[ 9 ] == PExt9 && Nat.gte( ARR_LEN2, zz, PExt )) )
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
			Nat.sub33From( ARR_LEN, PInv33, z );
		}
	}

	@Override
	protected void elTwice( int[] x, int[] z )
	{
		int c = Nat.shiftUpBit( ARR_LEN, x, 0, z );
		if( c != 0 || (z[ 4 ] == P4 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.add33To( ARR_LEN, PInv33, z );
		}
	}

}
