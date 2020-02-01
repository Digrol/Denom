package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Secp160r1 extends CustomFpCurve
{
	private static final int ARR_LEN = 5;
	private static final int ARR_LEN2 = 10;

	private static final long M = 0xFFFFFFFFL;

	// 2^160 - 2^31 - 1
	private static final int[] P = new int[] { 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExt = new int[] { 0x00000001, 0x40000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExtInv = new int[] { 0xFFFFFFFF, 0xBFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0x00000001 };
	private static final int P4 = 0xFFFFFFFF;
	private static final int PExt9 = 0xFFFFFFFF;
	private static final int PInv = 0x80000001;


	public Secp160r1()
	{
		super( P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", // p
			ARR_LEN, false );
		
		super.init( new Element(), new Point( null, null, null ), "1.3.132.0.8",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", // a
			"1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", // b
			"0100000000000000000001F4C8F927AED3CA752257", // order (n)
			"01", // cofactor (h)
			"04 4A96B5688EF573284664698968C38BB913CBFC82"
			+ " 23A628553168947D59DCC912042351377AC5FB32" ); // G point
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
			// Raise this element to the exponent 2^158 - 2^29 Breaking up the exponent's binary
			// representation into "repunits", we get: { 129 1s } { 29 0s } Therefore we need an
			// addition chain containing 129 (the length of the repunit) We use: 1, 2, 4, 8, 16, 32, 64,
			// 128, [129]

			int[] x1 = this.arr;
			if( Nat.isZero( ARR_LEN, x1 ) || Nat.isOne( ARR_LEN, x1 ) )
			{
				return this;
			}

			int[] x2 = new int[ ARR_LEN ];
			elSquare( x1, x2 );
			elMultiply( x2, x1, x2 );
			int[] x4 = new int[ ARR_LEN ];
			elSquareN( x2, 2, x4 );
			elMultiply( x4, x2, x4 );
			int[] x8 = x2;
			elSquareN( x4, 4, x8 );
			elMultiply( x8, x4, x8 );
			int[] x16 = x4;
			elSquareN( x8, 8, x16 );
			elMultiply( x16, x8, x16 );
			int[] x32 = x8;
			elSquareN( x16, 16, x32 );
			elMultiply( x32, x16, x32 );
			int[] x64 = x16;
			elSquareN( x32, 32, x64 );
			elMultiply( x64, x32, x64 );
			int[] x128 = x32;
			elSquareN( x64, 64, x128 );
			elMultiply( x128, x64, x128 );
			int[] x129 = x64;
			elSquare( x128, x129 );
			elMultiply( x129, x1, x129 );

			int[] t1 = x129;
			elSquareN( t1, 29, t1 );

			int[] t2 = x128;
			elSquare( t1, t2 );

			return Arrays.equals( x1, t2 ) ? new Element( t1 ) : null;
		}
	}

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		long x5 = xx[ 5 ] & M, x6 = xx[ 6 ] & M, x7 = xx[ 7 ] & M, x8 = xx[ 8 ] & M, x9 = xx[ 9 ] & M;

		long c = 0;
		c += (xx[ 0 ] & M) + x5 + (x5 << 31);
		z[ 0 ] = (int)c;
		c >>>= 32;
		c += (xx[ 1 ] & M) + x6 + (x6 << 31);
		z[ 1 ] = (int)c;
		c >>>= 32;
		c += (xx[ 2 ] & M) + x7 + (x7 << 31);
		z[ 2 ] = (int)c;
		c >>>= 32;
		c += (xx[ 3 ] & M) + x8 + (x8 << 31);
		z[ 3 ] = (int)c;
		c >>>= 32;
		c += (xx[ 4 ] & M) + x9 + (x9 << 31);
		z[ 4 ] = (int)c;
		c >>>= 32;

		elReduceInt( (int)c, z );
	}

	@Override
	protected void elReduceInt( int x, int[] z )
	{
		if( ((x != 0) && Nat.mulWordsAdd( ARR_LEN, PInv, x, z ) != 0) || (z[ 4 ] == P4 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.addWordTo( ARR_LEN, PInv, z );
		}
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		int c = Nat.add( ARR_LEN, x, y, z );
		if( c != 0 || (z[ 4 ] == P4 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.addWordTo( ARR_LEN, PInv, z );
		}
	}

	@Override
	protected void elAddOne( int[] x, int[] z )
	{
		int c = Nat.inc( ARR_LEN, x, z );
		if( c != 0 || (z[ 4 ] == P4 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.addWordTo( ARR_LEN, PInv, z );
		}
	}

	@Override
	protected void elMultiply( int[] x, int[] y, int[] z )
	{
		int[] tt = new int[ ARR_LEN2 ];
		Nat.mul( ARR_LEN, x, y, tt );
		elReduce( tt, z );
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
			Nat.subWordFrom( ARR_LEN, PInv, z );
		}
	}

	@Override
	protected void elTwice( int[] x, int[] z )
	{
		int c = Nat.shiftUpBit( ARR_LEN, x, 0, z );
		if( c != 0 || (z[ 4 ] == P4 && Nat.gte( ARR_LEN, z, P )) )
		{
			Nat.addWordTo( ARR_LEN, PInv, z );
		}
	}

}
