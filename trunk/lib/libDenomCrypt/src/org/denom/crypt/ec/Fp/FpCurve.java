package org.denom.crypt.ec.Fp;

import java.util.Random;
import java.math.BigInteger;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

/**
 * Elliptic curve over Fp
 */
public class FpCurve extends FpCurveAbstract
{
	BigInteger r;

	// -----------------------------------------------------------------------------------------------------------------
	public FpCurve( String oid, String pHex, String aHex, String bHex, String orderHex, String cofactorHex, String gPointHex )
	{
		super( pHex, false );
		this.r = calculateResidue( modP );
		super.init( new FpElement(), new FpPoint( null, null, null ), oid, aHex, bHex, orderHex, cofactorHex, gPointHex );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static BigInteger calculateResidue( BigInteger p )
	{
		int bitLength = p.bitLength();
		if( bitLength >= 96 )
		{
			BigInteger firstWord = p.shiftRight( bitLength - 64 );
			if( firstWord.longValue() == -1L )
			{
				return BigInteger.ONE.shiftLeft( bitLength ).subtract( p );
			}
		}
		return null;
	}


	// =================================================================================================================
	// POINT
	// =================================================================================================================

	private class FpPoint extends FpPointAbstract
	{
		private FpPoint( ECElement x, ECElement y )
		{
			super( x, y );
			MUST( (x == null) == (y == null) );
		}

		private FpPoint( ECElement x, ECElement y, ECElement[] zs )
		{
			super( x, y, zs );
		}

		@Override
		protected ECPoint create( ECElement x, ECElement y )
		{
			return new FpPoint( x, y );
		}

		@Override
		protected ECPoint create( ECElement x, ECElement y, ECElement[] zs )
		{
			return new FpPoint( x, y, zs );
		}


		public ECElement getZCoord( int index )
		{
			if( (index == 1) && isJacobianModified )
			{
				return getJacobianModifiedW();
			}

			return super.getZCoord( index );
		}

		// B.3 pg 62
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

			ECElement X1 = this.x;
			ECElement Y1 = this.y;
			ECElement X2 = b.x;
			ECElement Y2 = b.y;

			ECElement Z1 = this.zs[ 0 ];
			ECElement Z2 = b.zs[ 0 ];

			boolean Z1IsOne = Z1.isOne();

			ECElement X3, Y3, Z3, Z3Squared = null;

			if( !Z1IsOne && Z1.equals( Z2 ) )
			{
				ECElement dx = X1.subtract( X2 ), dy = Y1.subtract( Y2 );
				if( dx.isZero() )
				{
					if( dy.isZero() )
					{
						return twice();
					}
					return getInfinity();
				}

				ECElement C = dx.square();
				ECElement W1 = X1.multiply( C ), W2 = X2.multiply( C );
				ECElement A1 = W1.subtract( W2 ).multiply( Y1 );

				X3 = dy.square().subtract( W1 ).subtract( W2 );
				Y3 = W1.subtract( X3 ).multiply( dy ).subtract( A1 );
				Z3 = dx;

				Z3 = Z3.multiply( Z1 );
			}
			else
			{
				ECElement Z1Squared, U2, S2;
				if( Z1IsOne )
				{
					Z1Squared = Z1;
					U2 = X2;
					S2 = Y2;
				}
				else
				{
					Z1Squared = Z1.square();
					U2 = Z1Squared.multiply( X2 );
					ECElement Z1Cubed = Z1Squared.multiply( Z1 );
					S2 = Z1Cubed.multiply( Y2 );
				}

				boolean Z2IsOne = Z2.isOne();
				ECElement Z2Squared, U1, S1;
				if( Z2IsOne )
				{
					Z2Squared = Z2;
					U1 = X1;
					S1 = Y1;
				}
				else
				{
					Z2Squared = Z2.square();
					U1 = Z2Squared.multiply( X1 );
					ECElement Z2Cubed = Z2Squared.multiply( Z2 );
					S1 = Z2Cubed.multiply( Y1 );
				}

				ECElement H = U1.subtract( U2 );
				ECElement R = S1.subtract( S2 );

				// Check if b == this or b == -this
				if( H.isZero() )
				{
					if( R.isZero() )
					{
						// this == b, i.e. this must be doubled
						return this.twice();
					}

					// this == -b, i.e. the result is the point at infinity
					return getInfinity();
				}

				ECElement HSquared = H.square();
				ECElement G = HSquared.multiply( H );
				ECElement V = HSquared.multiply( U1 );

				X3 = R.square().add( G ).subtract( two( V ) );
				Y3 = ((FpElement)(V.subtract( X3 ))).multiplyMinusProduct( R, G, S1 );

				Z3 = H;
				if( !Z1IsOne )
				{
					Z3 = Z3.multiply( Z1 );
				}
				if( !Z2IsOne )
				{
					Z3 = Z3.multiply( Z2 );
				}

				if( Z3 == H )
				{
					Z3Squared = HSquared;
				}
			}

			if( isJacobianModified )
			{
				ECElement W3 = calculateJacobianModifiedW( Z3, Z3Squared );
				return new FpPoint( X3, Y3, new ECElement[] { Z3, W3 } );
			}
			return new FpPoint( X3, Y3, new ECElement[] { Z3 } );
		}


		// B.3 pg 62
		public ECPoint twice()
		{
			if( this.isInfinity() )
			{
				return this;
			}

			ECElement Y1 = this.y;
			if( Y1.isZero() )
			{
				return getInfinity();
			}

			if( isJacobianModified )
			{
				return twiceJacobianModified( true );
			}

			ECElement X1 = this.x;

			ECElement Z1 = this.zs[ 0 ];

			boolean Z1IsOne = Z1.isOne();

			ECElement Y1Squared = Y1.square();
			ECElement T = Y1Squared.square();

			ECElement a4 = getA();
			ECElement a4Neg = a4.negate();

			ECElement M, S;
			if( a4Neg.toBigInteger().equals( BigInteger.valueOf( 3 ) ) )
			{
				ECElement Z1Squared = Z1IsOne ? Z1 : Z1.square();
				M = three( X1.add( Z1Squared ).multiply( X1.subtract( Z1Squared ) ) );
				S = four( Y1Squared.multiply( X1 ) );
			}
			else
			{
				ECElement X1Squared = X1.square();
				M = three( X1Squared );
				if( Z1IsOne )
				{
					M = M.add( a4 );
				}
				else if( !a4.isZero() )
				{
					ECElement Z1Squared = Z1.square();
					ECElement Z1Pow4 = Z1Squared.square();
					if( a4Neg.bitLength() < a4.bitLength() )
					{
						M = M.subtract( Z1Pow4.multiply( a4Neg ) );
					}
					else
					{
						M = M.add( Z1Pow4.multiply( a4 ) );
					}
				}
				S = four( X1.multiply( Y1Squared ) );
			}

			ECElement X3 = M.square().subtract( two( S ) );
			ECElement Y3 = S.subtract( X3 ).multiply( M ).subtract( eight( T ) );

			ECElement Z3 = two( Y1 );
			if( !Z1IsOne )
			{
				Z3 = Z3.multiply( Z1 );
			}

			return new FpPoint( X3, Y3, new ECElement[] { Z3 } );
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

			ECElement Y1 = this.y;
			if( Y1.isZero() )
			{
				return b;
			}

			if( isJacobianModified )
			{
				return twiceJacobianModified( false ).add( b );
			}
			return twice().add( b );
		}


		@Override
		public ECPoint timesPow2( int e )
		{
			MUST( e >= 0, "'e' cannot be negative" );

			if( (e == 0) || this.isInfinity() )
			{
				return this;
			}
			if( e == 1 )
			{
				return twice();
			}

			ECElement Y1 = this.y;
			if( Y1.isZero() )
			{
				return getInfinity();
			}

			ECElement W1 = getA();
			ECElement X1 = this.x;
			ECElement Z1 = this.zs.length < 1 ? fromBigInteger( BigInteger.ONE ) : this.zs[ 0 ];

			if( !Z1.isOne() )
			{
				if( isJacobianModified )
				{
					W1 = getJacobianModifiedW();
				}
				else
				{
					W1 = calculateJacobianModifiedW( Z1, null );
				}
			}

			for( int i = 0; i < e; ++i )
			{
				if( Y1.isZero() )
				{
					return getInfinity();
				}

				ECElement X1Squared = X1.square();
				ECElement M = three( X1Squared );
				ECElement _2Y1 = two( Y1 );
				ECElement _2Y1Squared = _2Y1.multiply( Y1 );
				ECElement S = two( X1.multiply( _2Y1Squared ) );
				ECElement _4T = _2Y1Squared.square();
				ECElement _8T = two( _4T );

				if( !W1.isZero() )
				{
					M = M.add( W1 );
					W1 = two( _8T.multiply( W1 ) );
				}

				X1 = M.square().subtract( two( S ) );
				Y1 = M.multiply( S.subtract( X1 ) ).subtract( _8T );
				Z1 = Z1.isOne() ? _2Y1 : _2Y1.multiply( Z1 );
			}

			if( isJacobianModified )
			{
				return new FpPoint( X1, Y1, new ECElement[] { Z1, W1 } );
			}
			return new FpPoint( X1, Y1, new ECElement[] { Z1 } );
		}

		protected ECElement two( ECElement x )
		{
			return x.add( x );
		}

		protected ECElement three( ECElement x )
		{
			return two( x ).add( x );
		}

		protected ECElement four( ECElement x )
		{
			return two( two( x ) );
		}

		protected ECElement eight( ECElement x )
		{
			return four( two( x ) );
		}

		protected ECElement calculateJacobianModifiedW( ECElement Z, ECElement ZSquared )
		{
			ECElement a4 = getA();
			if( a4.isZero() || Z.isOne() )
			{
				return a4;
			}

			if( ZSquared == null )
			{
				ZSquared = Z.square();
			}

			ECElement W = ZSquared.square();
			ECElement a4Neg = a4.negate();
			if( a4Neg.bitLength() < a4.bitLength() )
			{
				W = W.multiply( a4Neg ).negate();
			}
			else
			{
				W = W.multiply( a4 );
			}
			return W;
		}

		protected ECElement getJacobianModifiedW()
		{
			ECElement W = this.zs[ 1 ];
			if( W == null )
			{
				// NOTE: Rarely, twicePlus will result in the need for a lazy W1 calculation here
				this.zs[ 1 ] = W = calculateJacobianModifiedW( this.zs[ 0 ], null );
			}
			return W;
		}

		protected FpPoint twiceJacobianModified( boolean calculateW )
		{
			ECElement X1 = this.x, Y1 = this.y, Z1 = this.zs[ 0 ], W1 = getJacobianModifiedW();

			ECElement X1Squared = X1.square();
			ECElement M = three( X1Squared ).add( W1 );
			ECElement _2Y1 = two( Y1 );
			ECElement _2Y1Squared = _2Y1.multiply( Y1 );
			ECElement S = two( X1.multiply( _2Y1Squared ) );
			ECElement X3 = M.square().subtract( two( S ) );
			ECElement _4T = _2Y1Squared.square();
			ECElement _8T = two( _4T );
			ECElement Y3 = M.multiply( S.subtract( X3 ) ).subtract( _8T );
			ECElement W3 = calculateW ? two( _8T.multiply( W1 ) ) : null;
			ECElement Z3 = Z1.isOne() ? _2Y1 : _2Y1.multiply( Z1 );

			return new FpPoint( X3, Y3, new ECElement[] { Z3, W3 } );
		}
	}

	// =================================================================================================================
	// ELEMENT
	// =================================================================================================================

	private class FpElement extends FpElementAbstract
	{
		BigInteger q;
		BigInteger x;

		private FpElement()
		{
			this.q = FpCurve.this.modP;
		}

		private FpElement( BigInteger x )
		{
			this.q = FpCurve.this.modP;
			this.x = x;
			MUST( (x != null) && (x.signum() >= 0) && (x.compareTo( q ) < 0) );
		}

		@Override
		public ECElement create( BigInteger x )
		{
			return new FpElement( x );
		}

		public BigInteger toBigInteger()
		{
			return x;
		}

		public ECElement add( ECElement b )
		{
			return new FpElement( modAdd( x, b.toBigInteger() ) );
		}

		public ECElement addOne()
		{
			BigInteger x2 = x.add( BigInteger.ONE );
			if( x2.compareTo( q ) == 0 )
			{
				x2 = BigInteger.ZERO;
			}
			return new FpElement( x2 );
		}

		public ECElement subtract( ECElement b )
		{
			return new FpElement( modSubtract( x, b.toBigInteger() ) );
		}

		public ECElement multiply( ECElement b )
		{
			return new FpElement( modMult( x, b.toBigInteger() ) );
		}

		private ECElement multiplyMinusProduct( ECElement b, ECElement x, ECElement y )
		{
			BigInteger ax = this.x, bx = b.toBigInteger(), xx = x.toBigInteger(), yx = y.toBigInteger();
			BigInteger ab = ax.multiply( bx );
			BigInteger xy = xx.multiply( yx );
			return new FpElement( modReduce( ab.subtract( xy ) ) );
		}

		public ECElement multiplyPlusProduct( ECElement b, ECElement x, ECElement y )
		{
			BigInteger ax = this.x, bx = b.toBigInteger(), xx = x.toBigInteger(), yx = y.toBigInteger();
			BigInteger ab = ax.multiply( bx );
			BigInteger xy = xx.multiply( yx );
			return new FpElement( modReduce( ab.add( xy ) ) );
		}

		public ECElement divide( ECElement b )
		{
			return new FpElement( modMult( x, modInverse( b.toBigInteger() ) ) );
		}

		public ECElement negate()
		{
			return x.signum() == 0 ? this : new FpElement( q.subtract( x ) );
		}

		public ECElement square()
		{
			return new FpElement( modMult( x, x ) );
		}

		public ECElement squarePlusProduct( ECElement x, ECElement y )
		{
			BigInteger ax = this.x, xx = x.toBigInteger(), yx = y.toBigInteger();
			BigInteger aa = ax.multiply( ax );
			BigInteger xy = xx.multiply( yx );
			return new FpElement( modReduce( aa.add( xy ) ) );
		}

		public ECElement invert()
		{
			return new FpElement( modInverse( x ) );
		}

		// D.1.4 91
		/**
		 * return a sqrt root - the routine verifies that the calculation returns the right value -
		 * if none exists it returns null.
		 */
		public ECElement sqrt()
		{
			if( this.isZero() || this.isOne() ) // earlier JDK compatibility
			{
				return this;
			}

			if( !q.testBit( 0 ) )
			{
				throw new RuntimeException( "not done yet" );
			}

			// note: even though this class implements ECConstants don't be tempted to
			// remove the explicit declaration, some J2ME environments don't cope.

			if( q.testBit( 1 ) ) // q == 4m + 3
			{
				BigInteger e = q.shiftRight( 2 ).add( BigInteger.ONE );
				return checkSqrt( new FpElement( x.modPow( e, q ) ) );
			}

			if( q.testBit( 2 ) ) // q == 8m + 5
			{
				BigInteger t1 = x.modPow( q.shiftRight( 3 ), q );
				BigInteger t2 = modMult( t1, x );
				BigInteger t3 = modMult( t2, t1 );

				if( t3.equals( BigInteger.ONE ) )
				{
					return checkSqrt( new FpElement( t2 ) );
				}

				BigInteger t4 = BigInteger.valueOf( 2 ).modPow( q.shiftRight( 2 ), q );
				BigInteger y = modMult( t2, t4 );

				return checkSqrt( new FpElement( y ) );
			}

			// q == 8m + 1

			BigInteger legendreExponent = q.shiftRight( 1 );
			if( !(x.modPow( legendreExponent, q ).equals( BigInteger.ONE )) )
			{
				return null;
			}

			BigInteger X = this.x;
			BigInteger fourX = modDouble( modDouble( X ) );

			BigInteger k = legendreExponent.add( BigInteger.ONE ), qMinusOne = q.subtract( BigInteger.ONE );

			BigInteger U, V;
			Random rand = new Random();
			do
			{
				BigInteger P;
				do
				{
					P = new BigInteger( q.bitLength(), rand );
				}
				while( P.compareTo( q ) >= 0 || !modReduce( P.multiply( P ).subtract( fourX ) ).modPow( legendreExponent, q ).equals( qMinusOne ) );

				BigInteger[] result = lucasSequence( P, X, k );
				U = result[ 0 ];
				V = result[ 1 ];

				if( modMult( V, V ).equals( fourX ) )
				{
					return new FpElement( modHalfAbs( V ) );
				}
			}
			while( U.equals( BigInteger.ONE ) || U.equals( qMinusOne ) );

			return null;
		}

		private ECElement checkSqrt( ECElement z )
		{
			return z.square().equals( this ) ? z : null;
		}

		private BigInteger[] lucasSequence( BigInteger P, BigInteger Q, BigInteger k )
		{
			int n = k.bitLength();
			int s = k.getLowestSetBit();

			BigInteger Uh = BigInteger.ONE;
			BigInteger Vl = BigInteger.valueOf( 2 );
			BigInteger Vh = P;
			BigInteger Ql = BigInteger.ONE;
			BigInteger Qh = BigInteger.ONE;

			for( int j = n - 1; j >= s + 1; --j )
			{
				Ql = modMult( Ql, Qh );

				if( k.testBit( j ) )
				{
					Qh = modMult( Ql, Q );
					Uh = modMult( Uh, Vh );
					Vl = modReduce( Vh.multiply( Vl ).subtract( P.multiply( Ql ) ) );
					Vh = modReduce( Vh.multiply( Vh ).subtract( Qh.shiftLeft( 1 ) ) );
				}
				else
				{
					Qh = Ql;
					Uh = modReduce( Uh.multiply( Vl ).subtract( Ql ) );
					Vh = modReduce( Vh.multiply( Vl ).subtract( P.multiply( Ql ) ) );
					Vl = modReduce( Vl.multiply( Vl ).subtract( Ql.shiftLeft( 1 ) ) );
				}
			}

			Ql = modMult( Ql, Qh );
			Qh = modMult( Ql, Q );
			Uh = modReduce( Uh.multiply( Vl ).subtract( Ql ) );
			Vl = modReduce( Vh.multiply( Vl ).subtract( P.multiply( Ql ) ) );
			Ql = modMult( Ql, Qh );

			for( int j = 1; j <= s; ++j )
			{
				Uh = modMult( Uh, Vl );
				Vl = modReduce( Vl.multiply( Vl ).subtract( Ql.shiftLeft( 1 ) ) );
				Ql = modMult( Ql, Ql );
			}

			return new BigInteger[] { Uh, Vl };
		}

		private BigInteger modAdd( BigInteger x1, BigInteger x2 )
		{
			BigInteger x3 = x1.add( x2 );
			if( x3.compareTo( q ) >= 0 )
			{
				x3 = x3.subtract( q );
			}
			return x3;
		}

		private BigInteger modDouble( BigInteger x )
		{
			BigInteger _2x = x.shiftLeft( 1 );
			if( _2x.compareTo( q ) >= 0 )
			{
				_2x = _2x.subtract( q );
			}
			return _2x;
		}

		private BigInteger modHalfAbs( BigInteger x )
		{
			if( x.testBit( 0 ) )
			{
				x = q.subtract( x );
			}
			return x.shiftRight( 1 );
		}

		private BigInteger modInverse( BigInteger x )
		{
			int bits = getFieldSize();
			int len = (bits + 31) >> 5;
			int[] p = Nat.fromBigInteger( bits, q );
			int[] n = Nat.fromBigInteger( bits, x );
			int[] z = new int[ len ];
			Nat.invert( p, n, z );
			return Nat.toBigInteger( len, z );
		}

		private BigInteger modMult( BigInteger x1, BigInteger x2 )
		{
			return modReduce( x1.multiply( x2 ) );
		}

		private BigInteger modReduce( BigInteger x )
		{
			if( r != null )
			{
				boolean negative = x.signum() < 0;
				if( negative )
				{
					x = x.abs();
				}
				int qLen = q.bitLength();
				boolean rIsOne = r.equals( BigInteger.ONE );
				while( x.bitLength() > (qLen + 1) )
				{
					BigInteger u = x.shiftRight( qLen );
					BigInteger v = x.subtract( u.shiftLeft( qLen ) );
					if( !rIsOne )
					{
						u = u.multiply( r );
					}
					x = u.add( v );
				}
				while( x.compareTo( q ) >= 0 )
				{
					x = x.subtract( q );
				}
				if( negative && x.signum() != 0 )
				{
					x = q.subtract( x );
				}
			}
			else
			{
				x = x.mod( q );
			}
			return x;
		}

		private BigInteger modSubtract( BigInteger x1, BigInteger x2 )
		{
			BigInteger x3 = x1.subtract( x2 );
			if( x3.signum() < 0 )
			{
				x3 = x3.add( q );
			}
			return x3;
		}

		public boolean equals( Object other )
		{
			if( other == this )
			{
				return true;
			}

			if( !(other instanceof FpElement) )
			{
				return false;
			}

			FpElement o = (FpElement)other;
			return q.equals( o.q ) && x.equals( o.x );
		}

		public int hashCode()
		{
			return q.hashCode() ^ x.hashCode();
		}
	}

}
