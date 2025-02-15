package org.denom.crypt.ec.Fp;

import java.math.BigInteger;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public abstract class FpCurveAbstract extends ECCurve
{
	protected final BigInteger modP;
	protected final int fieldSize;
	protected final boolean isJacobianModified;
	
	protected FpCurveAbstract( String PHex, boolean isJacobianModified )
	{
		this.isJacobianModified = isJacobianModified;
		this.modP = Hex2BigInt( PHex );
		this.fieldSize = modP.bitLength();
	}

	public final BigInteger getP()
	{
		return this.modP;
	}


	@Override
	protected ECPoint decompressPoint( int yTilde, BigInteger X1 )
	{
		ECElement x = this.fromBigInteger( X1 );
		ECElement rhs = x.square().add( this.getA() ).multiply( x ).add( this.getB() );
		ECElement y = rhs.sqrt();

		// If y is not a square, then we haven't got a point on the curve
		MUST( y != null, "Invalid point compression" );

		if( y.testBitZero() != (yTilde == 1) )
		{
			// Use the other root
			y = y.negate();
		}

		return this.createRawPoint( x, y );
	}


	@Override
	public final int getFieldSize()
	{
		return fieldSize;
	}

	public final int getNField()
	{
		return (fieldSize + 7) >>> 3;
	}

	private ECElement[] getInitialZCoords()
	{
		ECElement one = fromBigInteger( BigInteger.ONE );
		if( isJacobianModified )
		{
			return new ECElement[] { one, getA() };
		}
		return new ECElement[] { one };
	}

	// =================================================================================================================
	// POINT
	// =================================================================================================================

	protected abstract class FpPointAbstract extends ECPoint
	{
		protected FpPointAbstract( ECElement x, ECElement y )
		{
			super( x, y, getInitialZCoords() );
		}

		protected FpPointAbstract( ECElement x, ECElement y, ECElement[] zs )
		{
			super( x, y, zs );
		}


		@Override
		public ECPoint normalize()
		{
			if( this.isInfinity() )
			{
				return this;
			}

			ECElement Z1 = getZCoord( 0 );
			if( Z1.isOne() )
			{
				return this;
			}

			ECElement zInv = Z1.invert();
			ECElement zInv2 = zInv.square();
			ECElement zInv3 = zInv2.multiply( zInv );
			return createRawPoint( this.x.multiply( zInv2 ), this.y.multiply( zInv3 ) );
		}

		@Override
		protected boolean getCompressionYTilde()
		{
			return this.getAffineYCoord().testBitZero();
		}

		@Override
		protected boolean satisfiesCurveEquation()
		{
			ECElement X = this.x, Y = this.y, A = getA(), B = getB();
			ECElement lhs = Y.square();

			ECElement Z = this.zs[ 0 ];
			if( !Z.isOne() )
			{
				ECElement Z2 = Z.square(), Z4 = Z2.square(), Z6 = Z2.multiply( Z4 );
				A = A.multiply( Z4 );
				B = B.multiply( Z6 );
			}

			ECElement rhs = X.square().add( A ).multiply( X ).add( B );
			return lhs.equals( rhs );
		}

		@Override
		public final ECPoint negate()
		{
			if( this.isInfinity() )
			{
				return this;
			}

			return create( this.x, this.y.negate(), this.zs );
		}

	} // Point


	// =================================================================================================================
	// ELEMENT
	// =================================================================================================================

	protected abstract class FpElementAbstract extends ECElement
	{
		@Override
		public final int getFieldSize()
		{
			return FpCurveAbstract.this.getFieldSize();
		}
	}
	
}
