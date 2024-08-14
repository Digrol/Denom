package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;

import org.denom.crypt.ec.Nat;
import org.denom.crypt.ec.Fp.*;

abstract class CustomFpCurve extends FpCurveAbstract
{
	final int arrLen;
	final int arrLen2;
	final int[] P;

	// -----------------------------------------------------------------------------------------------------------------
	protected CustomFpCurve( int[] P, String modulePHex, int arrLen, boolean isJacobianModified )
 	{
		super( modulePHex, isJacobianModified );
		this.arrLen = arrLen;
		this.arrLen2 = arrLen * 2;
		this.P = P;
	}

	// =================================================================================================================
	// POINT
	// =================================================================================================================

	protected class Point extends FpPointAbstract
	{
		protected Point( ECElement x, ECElement y )
		{
			super( x, y );
		}

		protected Point( ECElement x, ECElement y, ECElement[] zs )
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

		Element elCreate( int[] x )
		{
			return (Element)((Element)myElement).create( x );
		}

		// -----------------------------------------------------------------------------------------------------------------
		@Override
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

			int c;
			int[] tt1 = new int[ arrLen2 ];
			int[] t2 = new int[ arrLen ];
			int[] t3 = new int[ arrLen ];
			int[] t4 = new int[ arrLen ];

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

				U1 = tt1;
				elMultiply( S1, X1.arr, U1 );

				elMultiply( S1, Z2.arr, S1 );
				elMultiply( S1, Y1.arr, S1 );
			}

			int[] H = new int[ arrLen ];
			elSubtract( U1, U2, H );

			int[] R = t2;
			elSubtract( S1, S2, R );

			// Check if b == this or b == -this
			if( Nat.isZero( arrLen, H ) )
			{
				if( Nat.isZero( arrLen, R ) )
				{
					// this == b, i.e. this must be doubled
					return this.twice();
				}

				// this == -b, i.e. the result is the point at infinity
				return getInfinity();
			}

			int[] HSquared = t3;
			elSquare( H, HSquared );

			int[] G = new int[ arrLen ];
			elMultiply( HSquared, H, G );

			int[] V = t3;
			elMultiply( HSquared, U1, V );

			elNegate( G, G );
			Nat.mul( arrLen, S1, G, tt1 );

			c = Nat.addBothTo( arrLen, V, V, G );
			elReduceInt( c, G );

			Element X3 = elCreate( t4 );
			elSquare( R, X3.arr );
			elSubtract( X3.arr, G, X3.arr );

			Element Y3 = elCreate( G );
			elSubtract( V, X3.arr, Y3.arr );
			elMultiplyAddToExt( Y3.arr, R, tt1 );
			elReduce( tt1, Y3.arr );

			Element Z3 = elCreate( H );
			if( !Z1IsOne )
			{
				elMultiply( Z3.arr, Z1.arr, Z3.arr );
			}
			if( !Z2IsOne )
			{
				elMultiply( Z3.arr, Z2.arr, Z3.arr );
			}

			return create( X3, Y3, new ECElement[] { Z3 } );
		}

		// -----------------------------------------------------------------------------------------------------------------
		@Override
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

			if( getA().isZero() ) // K case
			{
				Element X1 = (Element)this.x, Z1 = (Element)this.zs[ 0 ];

				int c;

				int[] Y1Squared = new int[ arrLen ];
				elSquare( Y1.arr, Y1Squared );

				int[] T = new int[ arrLen ];
				elSquare( Y1Squared, T );

				int[] M = new int[ arrLen ];
				elSquare( X1.arr, M );
				c = Nat.addBothTo( arrLen, M, M, M );
				elReduceInt( c, M );

				int[] S = Y1Squared;
				elMultiply( Y1Squared, X1.arr, S );
				c = Nat.shiftUpBits( arrLen, S, 2, 0 );
				elReduceInt( c, S );

				int[] t1 = new int[ arrLen ];
				c = Nat.shiftUpBits( arrLen, T, 3, 0, t1 );
				elReduceInt( c, t1 );

				Element X3 = elCreate( T );
				elSquare( M, X3.arr );
				elSubtract( X3.arr, S, X3.arr );
				elSubtract( X3.arr, S, X3.arr );

				Element Y3 = elCreate( S );
				elSubtract( S, X3.arr, Y3.arr );
				elMultiply( Y3.arr, M, Y3.arr );
				elSubtract( Y3.arr, t1, Y3.arr );

				Element Z3 = elCreate( M );
				elTwice( Y1.arr, Z3.arr );
				if( !Z1.isOne() )
				{
					elMultiply( Z3.arr, Z1.arr, Z3.arr );
				}

				return create( X3, Y3, new ECElement[] { Z3 } );

			}
			else // R case
			{
				Element X1 = (Element)this.x, Z1 = (Element)this.zs[ 0 ];

				int c;
				int[] t1 = new int[ arrLen ];
				int[] t2 = new int[ arrLen ];

				int[] Y1Squared = new int[ arrLen ];
				elSquare( Y1.arr, Y1Squared );

				int[] T = new int[ arrLen ];
				elSquare( Y1Squared, T );

				int[] Z1Squared = Z1.arr;
				if( !Z1.isOne() )
				{
					Z1Squared = t2;
					elSquare( Z1.arr, Z1Squared );
				}

				elSubtract( X1.arr, Z1Squared, t1 );

				int[] M = t2;
				elAdd( X1.arr, Z1Squared, M );
				elMultiply( M, t1, M );
				c = Nat.addBothTo( arrLen, M, M, M );
				elReduceInt( c, M );

				int[] S = Y1Squared;
				elMultiply( Y1Squared, X1.arr, S );
				c = Nat.shiftUpBits( arrLen, S, 2, 0 );
				elReduceInt( c, S );

				c = Nat.shiftUpBits( arrLen, T, 3, 0, t1 );
				elReduceInt( c, t1 );

				Element X3 = elCreate( T );
				elSquare( M, X3.arr );
				elSubtract( X3.arr, S, X3.arr );
				elSubtract( X3.arr, S, X3.arr );

				Element Y3 = elCreate( S );
				elSubtract( S, X3.arr, Y3.arr );
				elMultiply( Y3.arr, M, Y3.arr );
				elSubtract( Y3.arr, t1, Y3.arr );

				Element Z3 = elCreate( M );
				elTwice( Y1.arr, Z3.arr );
				if( !Z1.isOne() )
				{
					elMultiply( Z3.arr, Z1.arr, Z3.arr );
				}

				return create( X3, Y3, new ECElement[] { Z3 } );
			}
		}

	}

	// =================================================================================================================
	// ELEMENT
	// =================================================================================================================

	protected abstract class Element extends FpElementAbstract
	{
		protected int[] arr;

		protected abstract ECElement create( int[] x );

		@Override
		public final boolean isZero()
		{
			return Nat.isZero( arrLen, arr );
		}

		@Override
		public final boolean isOne()
		{
			return Nat.isOne( arrLen, arr );
		}

		@Override
		public final boolean testBitZero()
		{
			return Nat.getBit( arr, 0 ) == 1;
		}

		@Override
		public final BigInteger toBigInteger()
		{
			return Nat.toBigInteger( arrLen, arr );
		}

		@Override
		public ECElement add( ECElement b )
		{
			int[] z = new int[ arrLen ];
			elAdd( arr, ((Element)b).arr, z );
			return create( z );
		}

		@Override
		public ECElement addOne()
		{
			int[] z = new int[ arrLen ];
			elAddOne( arr, z );
			return create( z );
		}

		@Override
		public ECElement subtract( ECElement b )
		{
			int[] z = new int[ arrLen ];
			elSubtract( arr, ((Element)b).arr, z );
			return create( z );
		}

		@Override
		public ECElement multiply( ECElement b )
		{
			int[] z = new int[ arrLen ];
			elMultiply( arr, ((Element)b).arr, z );
			return create( z );
		}

		@Override
		public ECElement divide( ECElement b )
		{
			int[] z = new int[ arrLen ];
			Nat.invert( P, ((Element)b).arr, z );
			elMultiply( z, arr, z );
			return create( z );
		}

		@Override
		public ECElement negate()
		{
			int[] z = new int[ arrLen ];
			elNegate( arr, z );
			return create( z );
		}

		@Override
		public ECElement square()
		{
			int[] z = new int[ arrLen ];
			elSquare( arr, z );
			return create( z );
		}

		@Override
		public ECElement invert()
		{
			int[] z = new int[ arrLen ];
			Nat.invert( P, arr, z );
			return create( z );
		}

		@Override
		public final boolean equals( Object other )
		{
			if( other == this )
			{
				return true;
			}

			if( !(other instanceof Element) )
			{
				return false;
			}

			Element o = (Element)other;
			return Arrays.equals( arr, o.arr );
		}
	}

	// =================================================================================================================

	protected abstract void elReduce( int[] xx, int[] z );
	protected abstract void elReduceInt( int x, int[] z );


	protected void elAdd( int[] x, int[] y, int[] z ){}


	protected void elAddOne( int[] x, int[] z ) {}


	protected void elSubtract( int[] x, int[] y, int[] z ) {}


	protected void elTwice( int[] x, int[] z ) {}


	protected void elMultiplyAddToExt( int[] x, int[] y, int[] zz ) {}

	
	protected void elMultiply( int[] x, int[] y, int[] z )
	{
		int[] tt = new int[ arrLen2 ];
		Nat.mul( arrLen, x, y, tt );
		elReduce( tt, z );
	}


	protected void elNegate( int[] x, int[] z )
	{
		if( Nat.isZero( arrLen, x ) )
		{
			Nat.zero( arrLen, z );
		}
		else
		{
			Nat.sub( arrLen, P, x, z );
		}
	}


	protected void elSquare( int[] x, int[] z )
	{
		int[] tt = new int[ arrLen2 ];
		Nat.square( arrLen, x, tt );
		elReduce( tt, z );
	}


	protected void elSquareN( int[] x, int n, int[] z )
	{
		int[] tt = new int[ arrLen2 ];
		Nat.square( arrLen, x, tt );
		elReduce( tt, z );

		while( --n > 0 )
		{
			Nat.square( arrLen, z, tt );
			elReduce( tt, z );
		}
	}

}