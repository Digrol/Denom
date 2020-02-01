package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

// P-224
public class Secp224r1 extends CustomFpCurve
{
	private static final int ARR_LEN = 7;
	private static final int ARR_LEN2 = 14;

	private static final long M = 0xFFFFFFFFL;

	// 2^224 - 2^96 + 1
	private static final int[] P = new int[] { 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExt = new int[] { 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000002, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	private static final int[] PExtInv = new int[] { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001 };
	private static final int P6 = 0xFFFFFFFF;
	private static final int PExt13 = 0xFFFFFFFF;


	public Secp224r1()
	{
		super( P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", // p
			ARR_LEN, false );
		
		super.init( new Element(), new Point( null, null, null ), "1.3.132.0.33",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", // a
			"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", // b
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", // order (n)
			"01", // cofactor (h)
			"04 B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
			+ " BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34" ); // G point
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

		// -----------------------------------------------------------------------------------------------------------------
		private boolean isSquare( int[] x )
		{
			int[] t1 = new int[ ARR_LEN ];
			int[] t2 = new int[ ARR_LEN ];
			Nat.copy( ARR_LEN, x, t1 );

			for( int i = 0; i < 7; ++i )
			{
				Nat.copy( ARR_LEN, t1, t2 );
				elSquareN( t1, 1 << i, t1 );
				elMultiply( t1, t2, t1 );
			}

			elSquareN( t1, 95, t1 );
			return Nat.isOne( ARR_LEN, t1 );
		}

		private void RM( int[] nc, int[] d0, int[] e0, int[] d1, int[] e1, int[] f1, int[] t )
		{
			elMultiply( e1, e0, t );
			elMultiply( t, nc, t );
			elMultiply( d1, d0, f1 );
			elAdd( f1, t, f1 );
			elMultiply( d1, e0, t );
			Nat.copy( ARR_LEN, f1, d1 );
			elMultiply( e1, d0, e1 );
			elAdd( e1, t, e1 );
			elSquare( e1, f1 );
			elMultiply( f1, nc, f1 );
		}

		private void RP( int[] nc, int[] d1, int[] e1, int[] f1, int[] t )
		{
			Nat.copy( ARR_LEN, nc, f1 );

			int[] d0 = new int[ ARR_LEN ];
			int[] e0 = new int[ ARR_LEN ];

			for( int i = 0; i < 7; ++i )
			{
				Nat.copy( ARR_LEN, d1, d0 );
				Nat.copy( ARR_LEN, e1, e0 );

				int j = 1 << i;
				while( --j >= 0 )
				{
					RS( d1, e1, f1, t );
				}

				RM( nc, d0, e0, d1, e1, f1, t );
			}
		}


		private void RS( int[] d, int[] e, int[] f, int[] t )
		{
			elMultiply( e, d, e );
			elTwice( e, e );
			elSquare( d, t );
			elAdd( f, t, d );
			elMultiply( f, t, f );
			int c = Nat.shiftUpBits( ARR_LEN, f, 2, 0 );
			elReduceInt( c, f );
		}

		private boolean trySqrt( int[] nc, int[] r, int[] t )
		{
			int[] d1 = new int[ ARR_LEN ];
			Nat.copy( ARR_LEN, r, d1 );
			int[] e1 = new int[ ARR_LEN ];
			e1[ 0 ] = 1;
			int[] f1 = new int[ ARR_LEN ];
			RP( nc, d1, e1, f1, t );

			int[] d0 = new int[ ARR_LEN ];
			int[] e0 = new int[ ARR_LEN ];

			for( int k = 1; k < 96; ++k )
			{
				Nat.copy( ARR_LEN, d1, d0 );
				Nat.copy( ARR_LEN, e1, e0 );

				RS( d1, e1, f1, t );

				if( Nat.isZero( ARR_LEN, d1 ) )
				{
					Nat.invert( P, e0, t );
					elMultiply( t, d0, t );
					return true;
				}
			}

			return false;
		}

		/**
		 * return a sqrt root - the routine verifies that the calculation returns the right value - if
		 * none exists it returns null.
		 */
		@Override
		public ECElement sqrt()
		{
			int[] c = this.arr;
			if( Nat.isZero( ARR_LEN, c ) || Nat.isOne( ARR_LEN, c ) )
			{
				return this;
			}

			int[] nc = new int[ ARR_LEN ];
			elNegate( c, nc );

			int[] r = Nat.random( Secp224r1.P );
			int[] t = new int[ ARR_LEN ];

			if( !isSquare( c ) )
			{
				return null;
			}

			while( !trySqrt( nc, r, t ) )
			{
				elAddOne( r, r );
			}

			elSquare( t, r );

			return Arrays.equals( c, r ) ? new Element( t ) : null;
		}

	} // Element

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		long xx10 = xx[ 10 ] & M, xx11 = xx[ 11 ] & M, xx12 = xx[ 12 ] & M, xx13 = xx[ 13 ] & M;

		final long n = 1;

		long t0 = (xx[ 7 ] & M) + xx11 - n;
		long t1 = (xx[ 8 ] & M) + xx12;
		long t2 = (xx[ 9 ] & M) + xx13;

		long cc = 0;
		cc += (xx[ 0 ] & M) - t0;
		long z0 = cc & M;
		cc >>= 32;
		cc += (xx[ 1 ] & M) - t1;
		z[ 1 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 2 ] & M) - t2;
		z[ 2 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 3 ] & M) + t0 - xx10;
		long z3 = cc & M;
		cc >>= 32;
		cc += (xx[ 4 ] & M) + t1 - xx11;
		z[ 4 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 5 ] & M) + t2 - xx12;
		z[ 5 ] = (int)cc;
		cc >>= 32;
		cc += (xx[ 6 ] & M) + xx10 - xx13;
		z[ 6 ] = (int)cc;
		cc >>= 32;
		cc += n;

		z3 += cc;

		z0 -= cc;
		z[ 0 ] = (int)z0;
		cc = z0 >> 32;
		if( cc != 0 )
		{
			cc += (z[ 1 ] & M);
			z[ 1 ] = (int)cc;
			cc >>= 32;
			cc += (z[ 2 ] & M);
			z[ 2 ] = (int)cc;
			z3 += cc >> 32;
		}
		z[ 3 ] = (int)z3;
		cc = z3 >> 32;

		if( (cc != 0 && Nat.incAt( 7, z, 4 ) != 0) || (z[ 6 ] == P6 && Nat.gte( ARR_LEN, z, P )) )
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
			long xx07 = x & M;

			cc += (z[ 0 ] & M) - xx07;
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
			cc += (z[ 3 ] & M) + xx07;
			z[ 3 ] = (int)cc;
			cc >>= 32;
		}

		if( (cc != 0 && Nat.incAt( 7, z, 4 ) != 0) || (z[ 6 ] == P6 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		int c = Nat.add( ARR_LEN, x, y, z );
		if( c != 0 || (z[ 6 ] == P6 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	@Override
	protected void elAddOne( int[] x, int[] z )
	{
		int c = Nat.inc( ARR_LEN, x, z );
		if( c != 0 || (z[ 6 ] == P6 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
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
				Nat.incAt( ARR_LEN2, zz, PExtInv.length );
			}
		}
	}

	@Override
	protected void elSubtract( int[] x, int[] y, int[] z )
	{
		if( Nat.sub( ARR_LEN, x, y, z ) != 0 )
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
				Nat.decAt( 7, z, 4 );
			}
		}
	}

	@Override
	protected void elTwice( int[] x, int[] z )
	{
		int c = Nat.shiftUpBit( 7, x, 0, z );
		if( c != 0 || (z[ 6 ] == P6 && Nat.gte( ARR_LEN, z, P )) )
		{
			addPInvTo( z );
		}
	}

	private void addPInvTo( int[] z )
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
			Nat.incAt( 7, z, 4 );
		}
	}

}
