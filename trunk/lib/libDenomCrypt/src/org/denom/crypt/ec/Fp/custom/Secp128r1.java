package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Secp128r1 extends CustomFpCurve
{
	private static final long M = 0xFFFFFFFFL;
	private static final int ARR_LEN = 4;
	private static final int ARR_LEN2 = 8;

	// 2^128 - 2^97 - 1
	private static final int[] P = new int[] { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFD };
	private static final int[] PExt = new int[] { 0x00000001, 0x00000000, 0x00000000, 0x00000004, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000003, 0xFFFFFFFC };
	private static final int[] PExtInv = new int[] { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFB, 0x00000001, 0x00000000, 0xFFFFFFFC, 0x00000003 };
	private static final int P3s1 = 0xFFFFFFFD >>> 1;
	private static final int PExt7s1 = 0xFFFFFFFC >>> 1;


	public Secp128r1()
	{
		super( P, "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF", // p
			ARR_LEN, false );
		
		super.init( new Element(), new Point( null, null, null ), "1.3.132.0.28",
			"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC", // a
			"E87579C11079F43DD824993C2CEE5ED3", // b
			"FFFFFFFE0000000075A30D1B9038A115", // order (n)
			"01", // cofactor (h)
			"04 161FF7528B899B2D0C28607CA52C5B86"
			+ " CF5AC8395BAFEB13C02DA292DDED7A83" ); // G point
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

			this.arr = Nat.fromBigInteger( 128, X );
			if( ((arr[ 3 ] >>> 1) >= P3s1) && Nat.gte( ARR_LEN, arr, P ) )
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
			// Raise this element to the exponent 2^126 - 2^95 Breaking up the exponent's binary
			// representation into "repunits", we get: { 31 1s } { 95 0s } Therefore we need an addition
			// chain containing 31 (the length of the repunit) We use: 1, 2, 4, 8, 10, 20, 30, [31]

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
			int[] x8 = new int[ ARR_LEN ];
			elSquareN( x4, 4, x8 );
			elMultiply( x8, x4, x8 );
			int[] x10 = x4;
			elSquareN( x8, 2, x10 );
			elMultiply( x10, x2, x10 );
			int[] x20 = x2;
			elSquareN( x10, 10, x20 );
			elMultiply( x20, x10, x20 );
			int[] x30 = x8;
			elSquareN( x20, 10, x30 );
			elMultiply( x30, x10, x30 );
			int[] x31 = x10;
			elSquare( x30, x31 );
			elMultiply( x31, x1, x31 );

			int[] t1 = x31;
			elSquareN( t1, 95, t1 );

			int[] t2 = x30;
			elSquare( t1, t2 );

			return Arrays.equals( x1, t2 ) ? new Element( t1 ) : null;
		}
	}

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		long x0 = xx[ 0 ] & M, x1 = xx[ 1 ] & M, x2 = xx[ 2 ] & M, x3 = xx[ 3 ] & M;
		long x4 = xx[ 4 ] & M, x5 = xx[ 5 ] & M, x6 = xx[ 6 ] & M, x7 = xx[ 7 ] & M;

		x3 += x7;
		x6 += (x7 << 1);
		x2 += x6;
		x5 += (x6 << 1);
		x1 += x5;
		x4 += (x5 << 1);
		x0 += x4;
		x3 += (x4 << 1);

		z[ 0 ] = (int)x0;
		x1 += (x0 >>> 32);
		z[ 1 ] = (int)x1;
		x2 += (x1 >>> 32);
		z[ 2 ] = (int)x2;
		x3 += (x2 >>> 32);
		z[ 3 ] = (int)x3;

		elReduceInt( (int)(x3 >>> 32), z );
	}

	@Override
	protected void elReduceInt( int x, int[] z )
	{
		while( x != 0 )
		{
			long c, x4 = x & M;

			c = (z[ 0 ] & M) + x4;
			z[ 0 ] = (int)c;
			c >>= 32;
			if( c != 0 )
			{
				c += (z[ 1 ] & M);
				z[ 1 ] = (int)c;
				c >>= 32;
				c += (z[ 2 ] & M);
				z[ 2 ] = (int)c;
				c >>= 32;
			}
			c += (z[ 3 ] & M) + (x4 << 1);
			z[ 3 ] = (int)c;
			c >>= 32;
			x = (int)c;
		}
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		int c = Nat.add( ARR_LEN, x, y, z );
		if( c != 0 || ((z[ 3 ] >>> 1) >= P3s1 && Nat.gte( ARR_LEN, z, P )) )
		{
			elAddPInvTo( z );
		}
	}

	@Override
	protected void elAddOne( int[] x, int[] z )
	{
		int c = Nat.inc( ARR_LEN, x, z );
		if( c != 0 || ((z[ 3 ] >>> 1) >= P3s1 && Nat.gte( ARR_LEN, z, P )) )
		{
			elAddPInvTo( z );
		}
	}

	@Override
	protected void elMultiplyAddToExt( int[] x, int[] y, int[] zz )
	{
		int c = Nat.mulAddTo( ARR_LEN, x, y, zz );
		if( c != 0 || ((zz[ 7 ] >>> 1) >= PExt7s1 && Nat.gte( ARR_LEN2, zz, PExt )) )
		{
			Nat.addTo( PExtInv.length, PExtInv, zz );
		}
	}

	@Override
	protected void elSubtract( int[] x, int[] y, int[] z )
	{
		int c = Nat.sub( ARR_LEN, x, y, z );
		if( c != 0 )
		{
			elSubPInvFrom( z );
		}
	}

	@Override
	protected void elTwice( int[] x, int[] z )
	{
		int c = Nat.shiftUpBit( 4, x, 0, z );
		if( c != 0 || ((z[ 3 ] >>> 1) >= P3s1 && Nat.gte( ARR_LEN, z, P )) )
		{
			elAddPInvTo( z );
		}
	}


	private void elAddPInvTo( int[] z )
	{
		long c = (z[ 0 ] & M) + 1;
		z[ 0 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			c += (z[ 1 ] & M);
			z[ 1 ] = (int)c;
			c >>= 32;
			c += (z[ 2 ] & M);
			z[ 2 ] = (int)c;
			c >>= 32;
		}
		c += (z[ 3 ] & M) + 2;
		z[ 3 ] = (int)c;
	}


	private void elSubPInvFrom( int[] z )
	{
		long c = (z[ 0 ] & M) - 1;
		z[ 0 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			c += (z[ 1 ] & M);
			z[ 1 ] = (int)c;
			c >>= 32;
			c += (z[ 2 ] & M);
			z[ 2 ] = (int)c;
			c >>= 32;
		}
		c += (z[ 3 ] & M) - 2;
		z[ 3 ] = (int)c;
	}
}
