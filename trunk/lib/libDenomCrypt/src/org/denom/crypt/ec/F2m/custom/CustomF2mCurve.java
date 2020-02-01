package org.denom.crypt.ec.F2m.custom;

import java.math.BigInteger;
import org.denom.crypt.ec.*;
import org.denom.crypt.ec.F2m.*;

import static org.denom.Ex.MUST;

abstract class CustomF2mCurve extends F2mCurveAbstract
{
	final int arrLen;
	final int arrLen2;

	protected CustomF2mCurve(int m, int k1, int k2, int k3, int arrLen, boolean isKoblitz )
	{
		super( m, k1, k2, k3, isKoblitz );
		this.arrLen = arrLen;
		this.arrLen2 = arrLen * 2;
	}

	// =================================================================================================================
	// POINT
	// =================================================================================================================

	class Point extends F2mPointAbstract
	{
		Point( ECElement x, ECElement y )
		{
			super( x, y );
		}

		Point( ECElement x, ECElement y, ECElement[] zs )
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


		public ECElement getYCoord()
		{
			ECElement X = x, L = y;

			if( this.isInfinity() || X.isZero() )
			{
				return L;
			}

			// Y is actually Lambda (X + Y/X) here; convert to affine value on the fly
			ECElement Y = L.add( X ).multiply( X );

			ECElement Z = zs[ 0 ];
			if( !Z.isOne() )
			{
				Y = Y.divide( Z );
			}

			return Y;
		}

		protected boolean getCompressionYTilde()
		{
			ECElement X = this.getRawXCoord();
			if( X.isZero() )
			{
				return false;
			}

			ECElement Y = this.getRawYCoord();

			// Y is actually Lambda (X + Y/X) here
			return Y.testBitZero() != X.testBitZero();
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

			ECElement X1 = this.x;
			ECElement X2 = b.getRawXCoord();

			if( X1.isZero() )
			{
				if( X2.isZero() )
				{
					return getInfinity();
				}

				return b.add( this );
			}

			ECElement L1 = this.y, Z1 = this.zs[ 0 ];
			ECElement L2 = b.getRawYCoord(), Z2 = b.getZCoord( 0 );

			boolean Z1IsOne = Z1.isOne();
			ECElement U2 = X2, S2 = L2;
			if( !Z1IsOne )
			{
				U2 = U2.multiply( Z1 );
				S2 = S2.multiply( Z1 );
			}

			boolean Z2IsOne = Z2.isOne();
			ECElement U1 = X1, S1 = L1;
			if( !Z2IsOne )
			{
				U1 = U1.multiply( Z2 );
				S1 = S1.multiply( Z2 );
			}

			ECElement A = S1.add( S2 );
			ECElement B = U1.add( U2 );

			if( B.isZero() )
			{
				if( A.isZero() )
				{
					return twice();
				}

				return getInfinity();
			}

			ECElement X3, L3, Z3;
			if( X2.isZero() )
			{
				ECPoint p = this.normalize();
				X1 = p.getXCoord();
				ECElement Y1 = p.getYCoord();

				ECElement Y2 = L2;
				ECElement L = Y1.add( Y2 ).divide( X1 );

				X3 = L.square().add( L ).add( X1 ).add( getA() );
				if( X3.isZero() )
				{
					return new Point( X3, getB().sqrt() );
				}

				ECElement Y3 = L.multiply( X1.add( X3 ) ).add( X3 ).add( Y1 );
				L3 = Y3.divide( X3 ).add( X3 );
				Z3 = fromBigInteger( BigInteger.ONE );
			}
			else
			{
				B = B.square();

				ECElement AU1 = A.multiply( U1 );
				ECElement AU2 = A.multiply( U2 );

				X3 = AU1.multiply( AU2 );
				if( X3.isZero() )
				{
					return new Point( X3, getB().sqrt() );
				}

				ECElement ABZ2 = A.multiply( B );
				if( !Z2IsOne )
				{
					ABZ2 = ABZ2.multiply( Z2 );
				}

				L3 = AU2.add( B ).squarePlusProduct( ABZ2, L1.add( Z1 ) );

				Z3 = ABZ2;
				if( !Z1IsOne )
				{
					Z3 = Z3.multiply( Z1 );
				}
			}

			return new Point( X3, L3, new ECElement[] { Z3 } );
		}

		public ECPoint twice()
		{
			if( this.isInfinity() )
			{
				return this;
			}

			ECElement X1 = this.x;
			if( X1.isZero() )
			{
				// A point with X == 0 is it's own additive inverse
				return getInfinity();
			}

			ECElement L1 = this.y, Z1 = this.zs[ 0 ];

			boolean Z1IsOne = Z1.isOne();
			ECElement L1Z1 = Z1IsOne ? L1 : L1.multiply( Z1 );
			ECElement Z1Sq = Z1IsOne ? Z1 : Z1.square();
			ECElement a = getA();
			ECElement aZ1Sq = Z1IsOne ? a : a.multiply( Z1Sq );
			ECElement T = L1.square().add( L1Z1 ).add( aZ1Sq );
			if( T.isZero() )
			{
				return new Point( T, getB().sqrt() );
			}

			ECElement X3 = T.square();
			ECElement Z3 = Z1IsOne ? T : T.multiply( Z1Sq );

			ECElement X1Z1 = Z1IsOne ? X1 : X1.multiply( Z1 );
			ECElement L3 = X1Z1.squarePlusProduct( T, L1Z1 ).add( X3 ).add( Z3 );

			return new Point( X3, L3, new ECElement[] { Z3 } );
		}

		public ECPoint twicePlus( ECPoint b )
		{
			if( this.isInfinity() )
			{
				return b;
			}
			if( b.isInfinity() )
			{
				return twice();
			}

			ECElement X1 = this.x;
			if( X1.isZero() )
			{
				// A point with X == 0 is it's own additive inverse
				return b;
			}

			ECElement X2 = b.getRawXCoord(), Z2 = b.getZCoord( 0 );
			if( X2.isZero() || !Z2.isOne() )
			{
				return twice().add( b );
			}

			ECElement L1 = this.y, Z1 = this.zs[ 0 ];
			ECElement L2 = b.getRawYCoord();

			ECElement X1Sq = X1.square();
			ECElement L1Sq = L1.square();
			ECElement Z1Sq = Z1.square();
			ECElement L1Z1 = L1.multiply( Z1 );

			ECElement T = getA().multiply( Z1Sq ).add( L1Sq ).add( L1Z1 );
			ECElement L2plus1 = L2.addOne();
			ECElement A = getA().add( L2plus1 ).multiply( Z1Sq ).add( L1Sq ).multiplyPlusProduct( T, X1Sq, Z1Sq );
			ECElement X2Z1Sq = X2.multiply( Z1Sq );
			ECElement B = X2Z1Sq.add( T ).square();

			if( B.isZero() )
			{
				if( A.isZero() )
				{
					return b.twice();
				}

				return getInfinity();
			}

			if( A.isZero() )
			{
				return new Point( A, getB().sqrt() );
			}

			ECElement X3 = A.square().multiply( X2Z1Sq );
			ECElement Z3 = A.multiply( B ).multiply( Z1Sq );
			ECElement L3 = A.add( B ).square().multiplyPlusProduct( T, L2plus1, Z3 );

			return new Point( X3, L3, new ECElement[] { Z3 } );
		}

		public ECPoint negate()
		{
			if( this.isInfinity() )
			{
				return this;
			}

			ECElement X = this.x;
			if( X.isZero() )
			{
				return this;
			}

			// L is actually Lambda (X + Y/X) here
			ECElement L = this.y, Z = this.zs[ 0 ];
			return new Point( X, L.add( Z ), new ECElement[] { Z } );
		}

	}

	// =================================================================================================================
	// ELEMENT
	// =================================================================================================================

	protected abstract class Element extends F2mElementAbstract
	{
		protected final long[] arr;

		protected Element() { arr = null; }

		protected Element( BigInteger X )
		{
			MUST( (X != null) && (X.signum() >= 0) && (X.bitLength() <= m) );
			this.arr = Nat.fromBigInteger64( m, X );
		}

		protected Element( long[] x )
		{
			this.arr = x;
		}


		protected abstract Element create( long[] x );


		@Override
		public final boolean isOne()
		{
			return Nat.isOne64( arr );
		}


		@Override
		public final boolean isZero()
		{
			return Nat.isZero64( arr );
		}


		@Override
		public final boolean testBitZero()
		{
			return (arr[ 0 ] & 1L) != 0L;
		}


		@Override
		public final BigInteger toBigInteger()
		{
			return Nat.toBigInteger64( arr );
		}


		@Override
		public final ECElement add( ECElement b )
		{
			long[] z = new long[ arrLen ];
			CustomF2mCurve.add( arr, ((Element)b).arr, z );
			return create( z );
		}


		@Override
		public final ECElement addOne()
		{
			long[] z = new long[ arrLen ];
			CustomF2mCurve.addOne( arr, z );
			return create( z );
		}


		@Override
		public final ECElement subtract( ECElement b )
		{
			// Addition and subtraction are the same in F2m
			return add( b );
		}


		@Override
		public final ECElement divide( ECElement b )
		{
			return multiply( b.invert() );
		}


		@Override
		public final ECElement negate()
		{
			return this;
		}

	}

	// =================================================================================================================

	protected static void add( long[] x, long[] y, long[] z )
	{
		int len = x.length;
		for( int i = 0; i < len; ++i )
		{
			z[ i ] = x[ i ] ^ y[ i ];
		}
	}


	protected static void addOne( long[] x, long[] z )
	{
		System.arraycopy( x, 0, z, 0, x.length );
		z[ 0 ] ^= 1L;
	}

}