package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

// P-521
public class Secp521r1 extends CustomFpCurve
{
	private static final int ARR_LEN = 17;

	// 2^521 - 1
	private static final int[] P = {
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x1FF };
	private static final int P16 = 0x1FF;

	private static final long M = 0xFFFFFFFFL;


	public Secp521r1()
	{
		super( P, "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // p
			ARR_LEN, false );
		
		super.init( new Element(), new Point( null, null, null ), "1.3.132.0.35",
			"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", // a
			"0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", // b
			"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", // order (n)
			"01", // cofactor (h)
			"04 00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
			+ " 011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650" ); // G point
	}

	// =================================================================================================================
	// POINT
	// =================================================================================================================

	private class Point extends CustomFpCurve.Point
	{
		private Point( ECElement x, ECElement y )
		{
			super( x, y );
		}

		private Point( ECElement x, ECElement y, ECElement[] zs )
		{
			super( x, y, zs );
		}
		
		@Override
		protected ECPoint create( ECElement x, ECElement y )
		{
			return new Point( x, y );
		}

		@Override
		protected ECPoint create( ECElement x, ECElement y, ECElement[] zs )
		{
			return new Point( x, y, zs );
		}

		public ECPoint add( ECPoint b )
		{
			if( this.isInfinity() )
			{
				return b;
			}
			if( b.isInfinity() )
			{
				return this;
			}
			if( this == b )
			{
				return twice();
			}

			Element X1 = (Element)this.x, Y1 = (Element)this.y;
			Element X2 = (Element)b.getXCoord(), Y2 = (Element)b.getYCoord();

			Element Z1 = (Element)this.zs[ 0 ];
			Element Z2 = (Element)b.getZCoord( 0 );

			int[] t1 = new int[ 17 ];
			int[] t2 = new int[ 17 ];
			int[] t3 = new int[ 17 ];
			int[] t4 = new int[ 17 ];

			boolean Z1IsOne = Z1.isOne();
			int[] U2, S2;
			if( Z1IsOne )
			{
				U2 = X2.arr;
				S2 = Y2.arr;
			}
			else
			{
				S2 = t3;
				elSquare( Z1.arr, S2 );

				U2 = t2;
				elMultiply( S2, X2.arr, U2 );

				elMultiply( S2, Z1.arr, S2 );
				elMultiply( S2, Y2.arr, S2 );
			}

			boolean Z2IsOne = Z2.isOne();
			int[] U1, S1;
			if( Z2IsOne )
			{
				U1 = X1.arr;
				S1 = Y1.arr;
			}
			else
			{
				S1 = t4;
				elSquare( Z2.arr, S1 );

				U1 = t1;
				elMultiply( S1, X1.arr, U1 );

				elMultiply( S1, Z2.arr, S1 );
				elMultiply( S1, Y1.arr, S1 );
			}

			int[] H = new int[ 17 ];
			elSubtract( U1, U2, H );

			int[] R = t2;
			elSubtract( S1, S2, R );

			// Check if b == this or b == -this
			if( Nat.isZero( 17, H ) )
			{
				if( Nat.isZero( 17, R ) )
				{
					// this == b, i.e. this must be doubled
					return this.twice();
				}

				// this == -b, i.e. the result is the point at infinity
				return getInfinity();
			}

			int[] HSquared = t3;
			elSquare( H, HSquared );

			int[] G = new int[ 17 ];
			elMultiply( HSquared, H, G );

			int[] V = t3;
			elMultiply( HSquared, U1, V );

			elMultiply( S1, G, t1 );

			Element X3 = new Element( t4 );
			elSquare( R, X3.arr );
			elAdd( X3.arr, G, X3.arr );
			elSubtract( X3.arr, V, X3.arr );
			elSubtract( X3.arr, V, X3.arr );

			Element Y3 = new Element( G );
			elSubtract( V, X3.arr, Y3.arr );
			elMultiply( Y3.arr, R, t2 );
			elSubtract( t2, t1, Y3.arr );

			Element Z3 = new Element( H );
			if( !Z1IsOne )
			{
				elMultiply( Z3.arr, Z1.arr, Z3.arr );
			}
			if( !Z2IsOne )
			{
				elMultiply( Z3.arr, Z2.arr, Z3.arr );
			}

			return new Point( X3, Y3, new ECElement[] { Z3 } );
		}

		public ECPoint twice()
		{
			if( this.isInfinity() )
			{
				return this;
			}

			Element Y1 = (Element)this.y;
			if( Y1.isZero() )
			{
				return getInfinity();
			}

			Element X1 = (Element)this.x, Z1 = (Element)this.zs[ 0 ];

			int[] t1 = new int[ ARR_LEN ];
			int[] t2 = new int[ ARR_LEN ];

			int[] Y1Squared = new int[ ARR_LEN ];
			elSquare( Y1.arr, Y1Squared );

			int[] T = new int[ ARR_LEN ];
			elSquare( Y1Squared, T );

			boolean Z1IsOne = Z1.isOne();

			int[] Z1Squared = Z1.arr;
			if( !Z1IsOne )
			{
				Z1Squared = t2;
				elSquare( Z1.arr, Z1Squared );
			}

			elSubtract( X1.arr, Z1Squared, t1 );

			int[] M = t2;
			elAdd( X1.arr, Z1Squared, M );
			elMultiply( M, t1, M );
			Nat.addBothTo( ARR_LEN, M, M, M );
			elReduceInt( 0, M );

			int[] S = Y1Squared;
			elMultiply( Y1Squared, X1.arr, S );
			Nat.shiftUpBits( ARR_LEN, S, 2, 0 );
			elReduceInt( 0, S );

			Nat.shiftUpBits( ARR_LEN, T, 3, 0, t1 );
			elReduceInt( 0, t1 );

			Element X3 = new Element( T );
			elSquare( M, X3.arr );
			elSubtract( X3.arr, S, X3.arr );
			elSubtract( X3.arr, S, X3.arr );

			Element Y3 = new Element( S );
			elSubtract( S, X3.arr, Y3.arr );
			elMultiply( Y3.arr, M, Y3.arr );
			elSubtract( Y3.arr, t1, Y3.arr );

			Element Z3 = new Element( M );
			elTwice( Y1.arr, Z3.arr );
			if( !Z1IsOne )
			{
				elMultiply( Z3.arr, Z1.arr, Z3.arr );
			}

			return new Point( X3, Y3, new ECElement[] { Z3 } );
		}

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

			this.arr = Nat.fromBigInteger( 521, X );
			if( Arrays.equals( arr, P ) )
			{
				Nat.zero( ARR_LEN, arr );
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
			// Raise this element to the exponent 2^519

			int[] x1 = this.arr;
			if( Nat.isZero( ARR_LEN, x1 ) || Nat.isOne( ARR_LEN, x1 ) )
			{
				return this;
			}

			int[] t1 = new int[ ARR_LEN ];
			int[] t2 = new int[ ARR_LEN ];

			elSquareN( x1, 519, t1 );
			elSquare( t1, t2 );

			return Arrays.equals( x1, t2 ) ? new Element( t1 ) : null;
		}
	}

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		int xx32 = xx[ 32 ];
		int c = Nat.shiftDownBits( 16, xx, 16, 9, xx32, z, 0 ) >>> 23;
		c += xx32 >>> 9;
		c += Nat.addTo( 16, xx, z );
		if( c > P16 || (c == P16 && Arrays.equals( z, P )) )
		{
			c += Nat.inc( 16, z );
			c &= P16;
		}
		z[ 16 ] = c;
	}

	@Override
	protected void elReduceInt( int dummy, int[] z )
	{
		int z16 = z[ 16 ];
		int c = Nat.addWordTo( 16, z16 >>> 9, z ) + (z16 & P16);
		if( c > P16 || (c == P16 && Arrays.equals( z, P )) )
		{
			c += Nat.inc( 16, z );
			c &= P16;
		}
		z[ 16 ] = c;
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		int c = Nat.add( 16, x, y, z ) + x[ 16 ] + y[ 16 ];
		if( c > P16 || (c == P16 && Arrays.equals( z, P )) )
		{
			c += Nat.inc( 16, z );
			c &= P16;
		}
		z[ 16 ] = c;
	}

	@Override
	protected void elAddOne( int[] x, int[] z )
	{
		int c = Nat.inc( 16, x, z ) + x[ 16 ];
		if( c > P16 || (c == P16 && Arrays.equals( z, P )) )
		{
			c += Nat.inc( 16, z );
			c &= P16;
		}
		z[ 16 ] = c;
	}

	@Override
	protected void elSquare( int[] x, int[] z )
	{
		int[] tt = new int[ 33 ];
		implSquare( x, tt );
		elReduce( tt, z );
	}

	@Override
	protected void elSquareN( int[] x, int n, int[] z )
	{
		int[] tt = new int[ 33 ];
		implSquare( x, tt );
		elReduce( tt, z );

		while( --n > 0 )
		{
			implSquare( z, tt );
			elReduce( tt, z );
		}
	}

	@Override
	protected void elSubtract( int[] x, int[] y, int[] z )
	{
		int c = Nat.sub( 16, x, y, z ) + x[ 16 ] - y[ 16 ];
		if( c < 0 )
		{
			c += Nat.dec( 16, z );
			c &= P16;
		}
		z[ 16 ] = c;
	}

	@Override
	protected void elTwice( int[] x, int[] z )
	{
		int x16 = x[ 16 ];
		int c = Nat.shiftUpBit( 16, x, x16 << 23, z ) | (x16 << 1);
		z[ 16 ] = c & P16;
	}

	private int addTo( int len, int[] x, int xOff, int[] z, int zOff, int cIn )
	{
		long c = cIn & M;
		for( int i = 0; i < len; ++i )
		{
			c += (x[ xOff + i ] & M) + (z[ zOff + i ] & M);
			z[ zOff + i ] = (int)c;
			c >>>= 32;
		}
		return (int)c;
	}

	private boolean gte( int len, int[] x, int xOff, int[] y, int yOff )
	{
		for( int i = len - 1; i >= 0; --i )
		{
			int x_i = x[ xOff + i ] ^ Integer.MIN_VALUE;
			int y_i = y[ yOff + i ] ^ Integer.MIN_VALUE;
			if( x_i < y_i )
				return false;
			if( x_i > y_i )
				return true;
		}
		return true;
	}

	private void implSquare( int[] x, int[] zz )
	{
		final int LEN = 8;
		Nat.square( LEN, x, zz );
		Nat.square( LEN, x, 8, zz, 16 );

		int c24 = Nat.addTo( LEN, zz, 8, zz, 16 );
		System.arraycopy( zz, 16, zz, 8, LEN );
		int c16 = c24 + Nat.addTo( LEN, zz, 0, zz, 8 );
		c24 += addTo( LEN, zz, 24, zz, 16, c16 );

		int[] dx = new int[ LEN ];

		if( gte( LEN, x, 0, x, 8 ) )
		{
			Nat.sub( LEN, x, 0, x, 8, dx, 0 );
		}
		else
		{
			Nat.sub( LEN, x, 8, x, 0, dx, 0 );
		}

		int[] tt = new int[ LEN * 2 ];
		Nat.square( LEN, dx, tt );

		c24 += Nat.subFrom( 16, tt, 0, zz, 8 );
		Nat.addWordAt( 32, c24, zz, 24 );

		int x16 = x[ 16 ];
		zz[ 32 ] = Nat.mulWordAddTo( 16, x16 << 1, x, 0, zz, 16 ) + (x16 * x16);
	}


}
