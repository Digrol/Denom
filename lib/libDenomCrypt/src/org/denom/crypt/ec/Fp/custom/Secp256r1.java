package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

// P-256
public class Secp256r1 extends CustomFpCurve
{
	private static final long M = 0xFFFFFFFFL;
	private static final int ARR_LEN = 8;
	private static final int ARR_LEN2 = 16;

	// 2^256 - 2^224 + 2^192 + 2^96 - 1
	private static final int[] P = new int[] { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF };
	private static final int[] PExt = new int[] { 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0x00000001, 0xFFFFFFFE, 0x00000001, 0xFFFFFFFE, 0x00000001, 0x00000001, 0xFFFFFFFE, 0x00000002, 0xFFFFFFFE };
	private static final int P7 = 0xFFFFFFFF;
	private static final int PExt15s1 = 0xFFFFFFFE >>> 1;


	public Secp256r1()
	{
		super( P, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", // p
			ARR_LEN, false );
		
		super.init( new Element(), new Point( null, null, null ), "1.2.840.10045.3.1.7",
			"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", // a
			"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", // b
			"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", // order (n)
			"01", // cofactor (h)
			"04 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
			+ " 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5" ); // G point
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

			this.arr = Nat.fromBigInteger( 256, X );
			if( (arr[ 7 ] == P7) && Nat.gte( ARR_LEN, arr, P ) )
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
		public ECElement create( int[] x )
		{
			return new Element( x );
		}

		@Override
		/**
		 * return a sqrt root - the routine verifies that the calculation returns the right value -
		 * if none exists it returns null.
		 */
		public ECElement sqrt()
		{
			// Raise this element to the exponent 2^254 - 2^222 + 2^190 + 2^94

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

			elSquareN( t1, 32, t1 );
			elMultiply( t1, x1, t1 );

			elSquareN( t1, 96, t1 );
			elMultiply( t1, x1, t1 );
			
			elSquareN( t1, 94, t1 );
			elSquare( t1, t2 );

			return Arrays.equals( x1, t2 ) ? new Element( t1 ) : null;
		}

	} // Element

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		long xx08 = xx[ 8 ] & M, xx09 = xx[ 9 ] & M, xx10 = xx[ 10 ] & M, xx11 = xx[ 11 ] & M;
		long xx12 = xx[ 12 ] & M, xx13 = xx[ 13 ] & M, xx14 = xx[ 14 ] & M, xx15 = xx[ 15 ] & M;

		final long n = 6;

		xx08 -= n;

		long t0 = xx08 + xx09;
		long t1 = xx09 + xx10;
		long t2 = xx10 + xx11 - xx15;
		long t3 = xx11 + xx12;
		long t4 = xx12 + xx13;
		long t5 = xx13 + xx14;
		long t6 = xx14 + xx15;
		long t7 = t5 - t0;

		long cc = 0;
		cc += (xx[ 0 ] & M) - t3 - t7;
		z[ 0 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 1 ] & M) + t1 - t4 - t6;
		z[ 1 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 2 ] & M) + t2 - t5;
		z[ 2 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 3 ] & M) + (t3 << 1) + t7 - t6;
		z[ 3 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 4 ] & M) + (t4 << 1) + xx14 - t1;
		z[ 4 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 5 ] & M) + (t5 << 1) - t2;
		z[ 5 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 6 ] & M) + (t6 << 1) + t7;
		z[ 6 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 7 ] & M) + (xx15 << 1) + xx08 - t2 - t4;
		z[ 7 ] = (int)cc;
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
			long xx08 = x & M;

			cc += (z[ 0 ] & M) + xx08;
			z[ 0 ] = (int)cc;
			cc >>= 32;
			if( cc != 0 )
			{
				cc += (z[ 1 ] & M);
				z[ 1 ] = (int)cc;
				cc >>= 32;
				cc += (z[ 2 ] & M);
				z[ 2 ] = (int)cc;
				cc >>= 32;
			}
			cc += (z[ 3 ] & M) - xx08;
			z[ 3 ] = (int)cc;
			cc >>= 32;
			if( cc != 0 )
			{
				cc += (z[ 4 ] & M);
				z[ 4 ] = (int)cc;
				cc >>= 32;
				cc += (z[ 5 ] & M);
				z[ 5 ] = (int)cc;
				cc >>= 32;
			}
			cc += (z[ 6 ] & M) - xx08;
			z[ 6 ] = (int)cc;
			cc >>= 32;
			cc += (z[ 7 ] & M) + xx08;
			z[ 7 ] = (int)cc;
			cc >>= 32;
		}

		if( cc != 0 || (z[ 7 ] == P7 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		int C = Nat.add( ARR_LEN, x, y, z );
		if( C != 0 || (z[ 7 ] == P7 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	@Override
	protected void elAddOne( int[] x, int[] z )
	{
		int c = Nat.inc( ARR_LEN, x, z );
		if( c != 0 || (z[ 7 ] == P7 && Nat.gte( ARR_LEN, z, P )) )
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
			c += (z[ 2 ] & M);
			z[ 2 ] = (int)c;
			c >>= 32;
		}
		c += (z[ 3 ] & M) - 1;
		z[ 3 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			c += (z[ 4 ] & M);
			z[ 4 ] = (int)c;
			c >>= 32;
			c += (z[ 5 ] & M);
			z[ 5 ] = (int)c;
			c >>= 32;
		}
		c += (z[ 6 ] & M) - 1;
		z[ 6 ] = (int)c;
		c >>= 32;
		c += (z[ 7 ] & M) + 1;
		z[ 7 ] = (int)c;
	}

	@Override
	protected void elSubtract( int[] x, int[] y, int[] z )
	{
		if( Nat.sub( ARR_LEN, x, y, z ) != 0 )
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
			c += (z[ 3 ] & M) + 1;
			z[ 3 ] = (int)c;
			c >>= 32;
			if( c != 0 )
			{
				c += (z[ 4 ] & M);
				z[ 4 ] = (int)c;
				c >>= 32;
				c += (z[ 5 ] & M);
				z[ 5 ] = (int)c;
				c >>= 32;
			}
			c += (z[ 6 ] & M) + 1;
			z[ 6 ] = (int)c;
			c >>= 32;
			c += (z[ 7 ] & M) - 1;
			z[ 7 ] = (int)c;
		}
	}

	@Override
	protected void elTwice( int[] x, int[] z )
	{
		int c = Nat.shiftUpBit( ARR_LEN, x, 0, z );
		if( c != 0 || (z[ 7 ] == P7 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
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
		if( c != 0 || ((zz[ 15 ] >>> 1) >= PExt15s1 && Nat.gte( ARR_LEN2, zz, PExt )) )
		{
			Nat.subFrom( ARR_LEN2, PExt, zz );
		}
	}
}
