package org.denom.crypt.ec.F2m;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Elliptic curves over F2m. The Weierstrass equation is given by
 * 'y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b'.
 */
public class F2mCurve extends F2mCurveAbstract
{
	/**
	 * Constructor for Pentanomial Polynomial Basis (PPB).
	 * @param m The exponent 'm' of 'F<sub>2<sup>m</sup></sub>'.
	 * @param k1 The integer 'k1' where 'x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1' represents the reduction
	 * polynomial 'f(z)'.
	 * @param k2 The integer 'k2' where 'x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1' represents the reduction
	 * polynomial 'f(z)'.
	 * @param k3 The integer 'k3' where 'x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1' represents the reduction
	 * polynomial 'f(z)'.
	 * @param a The coefficient 'a' in the Weierstrass equation for non-supersingular
	 * elliptic curves over 'F<sub>2<sup>m</sup></sub>'.
	 * @param b The coefficient 'b' in the Weierstrass equation for non-supersingular
	 * elliptic curves over 'F<sub>2<sup>m</sup></sub>'.
	 * @param order The order of the main subgroup of the elliptic curve.
	 * @param cofactor The cofactor of the elliptic curve, i.e.
	 * '#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n'.
	 */
	public F2mCurve( String oid, int m, int k1, int k2, int k3, String aHex, String bHex,
			String orderHex, String cofactorHex, String gPointHex )
	{
		super( m, k1, k2, k3, isKoblitzCurve( Hex2BigInt( aHex ), Hex2BigInt( bHex ) ) );
		super.init( new F2mElement(), new F2mPoint( null, null, null ),
				oid, aHex, bHex, orderHex, cofactorHex, gPointHex );
	}


	// =================================================================================================================
	// POINT
	// =================================================================================================================

	private class F2mPoint extends F2mPointAbstract
	{
		private F2mPoint( ECElement x, ECElement y )
		{
			super( x, y );
		}


		private F2mPoint(ECElement x, ECElement y, ECElement[] zs )
		{
			super( x, y, zs );
		}

		@Override
		protected ECPoint create( ECElement x, ECElement y )
		{
			return new F2mPoint( x, y );
		}

		@Override
		protected ECPoint create( ECElement x, ECElement y, ECElement[] zs )
		{
			return new F2mPoint( x, y, zs );
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
			ECElement X2 = b.x;

			if( X1.isZero() )
			{
				if( X2.isZero() )
				{
					return getInfinity();
				}

				return b.add( this );
			}

			ECElement L1 = this.y, Z1 = this.zs[ 0 ];
			ECElement L2 = b.y, Z2 = b.zs[ 0 ];

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
					return new F2mPoint( X3, getB().sqrt() );
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
					return new F2mPoint( X3, getB().sqrt() );
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

			return new F2mPoint( X3, L3, new ECElement[] { Z3 } );
		}

		// -----------------------------------------------------------------------------------------------------------------
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
				return new F2mPoint( T, getB().sqrt() );
			}

			ECElement X3 = T.square();
			ECElement Z3 = Z1IsOne ? T : T.multiply( Z1Sq );

			ECElement b = getB();
			ECElement L3;
			if( b.bitLength() < (getFieldSize() >> 1) )
			{
				ECElement t1 = L1.add( X1 ).square();
				ECElement t2;
				if( b.isOne() )
				{
					t2 = aZ1Sq.add( Z1Sq ).square();
				}
				else
				{
					t2 = aZ1Sq.squarePlusProduct( b, Z1Sq.square() );
				}
				L3 = t1.add( T ).add( Z1Sq ).multiply( t1 ).add( t2 ).add( X3 );
				if( a.isZero() )
				{
					L3 = L3.add( Z3 );
				}
				else if( !a.isOne() )
				{
					L3 = L3.add( a.addOne().multiply( Z3 ) );
				}
			}
			else
			{
				ECElement X1Z1 = Z1IsOne ? X1 : X1.multiply( Z1 );
				L3 = X1Z1.squarePlusProduct( T, L1Z1 ).add( X3 ).add( Z3 );
			}

			return new F2mPoint( X3, L3, new ECElement[] { Z3 } );
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

			// NOTE: twicePlus() only optimized for lambda-affine argument
			ECElement X2 = b.x, Z2 = b.zs[ 0 ];
			if( X2.isZero() || !Z2.isOne() )
			{
				return twice().add( b );
			}

			ECElement L1 = this.y, Z1 = this.zs[ 0 ];
			ECElement L2 = b.y;

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
				return new F2mPoint( A, getB().sqrt() );
			}

			ECElement X3 = A.square().multiply( X2Z1Sq );
			ECElement Z3 = A.multiply( B ).multiply( Z1Sq );
			ECElement L3 = A.add( B ).square().multiplyPlusProduct( T, L2plus1, Z3 );

			return new F2mPoint( X3, L3, new ECElement[] { Z3 } );
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
			return new F2mPoint( X, L.add( Z ), new ECElement[] { Z } );
		}
	}

	// =================================================================================================================
	// ELEMENT
	// =================================================================================================================

	/**
	 * Elements of the finite field 'F<sub>2<sup>m</sup></sub>' in polynomial basis (PB)
	 * representation. Both trinomial (TPB) and pentanomial (PPB) polynomial basis representations are
	 * supported. Gaussian normal basis (GNB) representation is not supported.
	 */
	private class F2mElement extends F2mElementAbstract
	{
		public LongArray x;

		protected F2mElement() {}

		public F2mElement( LongArray x )
		{
			this.x = x;
		}

		@Override
		public ECElement create( BigInteger x )
		{
			return new F2mElement( new LongArray( x ) );
		}

		public int bitLength()
		{
			return x.degree();
		}

		public boolean isOne()
		{
			return x.isOne();
		}

		public boolean isZero()
		{
			return x.isZero();
		}

		public boolean testBitZero()
		{
			return x.testBitZero();
		}

		public BigInteger toBigInteger()
		{
			return x.toBigInteger();
		}

		public ECElement add( final ECElement b )
		{
			// No check performed here for performance reasons. Instead the
			// elements involved are checked in ECPoint.F2m
			// checkFieldElements(this, b);
			LongArray iarrClone = (LongArray)this.x.clone();
			F2mElement bF2m = (F2mElement)b;
			iarrClone.addShiftedByWords( bF2m.x, 0 );
			return new F2mElement( iarrClone );
		}

		public ECElement addOne()
		{
			return new F2mElement( x.addOne() );
		}

		public ECElement subtract( final ECElement b )
		{
			// Addition and subtraction are the same in F2m
			return add( b );
		}

		public ECElement multiply( final ECElement b )
		{
			// Right-to-left comb multiplication in the LongArray
			// Input: Binary polynomials a(z) and b(z) of degree at most m-1
			// Output: c(z) = a(z) * b(z) mod f(z)

			// No check performed here for performance reasons. Instead the
			// elements involved are checked in ECPoint.F2m
			// checkFieldElements(this, b);
			return new F2mElement( x.modMultiply( ((F2mElement)b).x, m, ks ) );
		}

		public ECElement multiplyPlusProduct( ECElement b, ECElement x, ECElement y )
		{
			LongArray ax = this.x, bx = ((F2mElement)b).x, xx = ((F2mElement)x).x, yx = ((F2mElement)y).x;

			LongArray ab = ax.multiply( bx );
			LongArray xy = xx.multiply( yx );

			if( ab == ax || ab == bx )
			{
				ab = (LongArray)ab.clone();
			}

			ab.addShiftedByWords( xy, 0 );
			ab.reduce( m, ks );

			return new F2mElement( ab );
		}

		public ECElement divide( final ECElement b )
		{
			// There may be more efficient implementations
			ECElement bInv = b.invert();
			return multiply( bInv );
		}

		public ECElement negate()
		{
			// -x == x holds for all x in F2m
			return this;
		}

		public ECElement square()
		{
			return new F2mElement( x.modSquare( m, ks ) );
		}

		public ECElement squarePlusProduct( ECElement x, ECElement y )
		{
			LongArray ax = this.x, xx = ((F2mElement)x).x, yx = ((F2mElement)y).x;

			LongArray aa = ax.square();
			LongArray xy = xx.multiply( yx );

			if( aa == ax )
			{
				aa = (LongArray)aa.clone();
			}

			aa.addShiftedByWords( xy, 0 );
			aa.reduce( m, ks );

			return new F2mElement( aa );
		}

		public ECElement squarePow( int pow )
		{
			return pow < 1 ? this : new F2mElement( x.modSquareN( pow, m, ks ) );
		}

		public ECElement invert()
		{
			return new F2mElement( this.x.modInverse( m, ks ) );
		}

		public ECElement sqrt()
		{
			return (x.isZero() || x.isOne()) ? this : squarePow( m - 1 );
		}

		public boolean equals( Object anObject )
		{
			if( anObject == this )
			{
				return true;
			}

			if( !(anObject instanceof F2mElement) )
			{
				return false;
			}

			F2mElement b = (F2mElement)anObject;

			return this.x.equals( b.x );
		}

		public int hashCode()
		{
			return x.hashCode() ^ m ^ Arrays.hashCode( ks );
		}
	}

}
