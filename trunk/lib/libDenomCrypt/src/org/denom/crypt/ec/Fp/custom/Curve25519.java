package org.denom.crypt.ec.Fp.custom;

import java.math.BigInteger;
import java.util.Arrays;
import org.denom.crypt.ec.*;

import static org.denom.Ex.MUST;

public class Curve25519 extends CustomFpCurve
{
	private static final int ARR_LEN = 8;
	private static final int ARR_LEN2 = 16;

	private static final long M = 0xFFFFFFFFL;

	// 2^255 - 2^4 - 2^1 - 1
	private static final int[] P = { 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF };
	private static final int P7 = 0x7FFFFFFF;
	private static final int[] PExt = {
			0x00000169, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x3FFFFFFF };
	private static final int PInv = 0x13;

	// Calculated as ECConstants.TWO.modPow(Q.shiftRight(2), Q)
	private static final int[] PRECOMP_POW2 = { 0x4a0ea0b0, 0xc4ee1b27, 0xad2fe478, 0x2f431806, 0x3dfbd7a7, 0x2b4d0099, 0x4fc1df0b, 0x2b832480 };


	public Curve25519()
	{
		super( P, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", // p
			ARR_LEN, true );
		
		super.init( new Element(), new Point( null, null, null ), "",
			"2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144", // a
			"7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864", // b
			"1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", // order (n)
			"08", // cofactor (h)
			"04 2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD245A"
			+ " 20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9" ); // G point
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

		public ECElement getZCoord( int index )
		{
			if( index == 1 )
			{
				return getJacobianModifiedW();
			}

			return super.getZCoord( index );
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

			Element X1 = (Element)this.x, Y1 = (Element)this.y,
					Z1 = (Element)this.zs[ 0 ];
			Element X2 = (Element)b.getXCoord(), Y2 = (Element)b.getYCoord(),
					Z2 = (Element)b.getZCoord( 0 );

			int c;
			int[] tt1 = new int[ ARR_LEN2 ];
			int[] t2 = new int[ ARR_LEN ];
			int[] t3 = new int[ ARR_LEN ];
			int[] t4 = new int[ ARR_LEN ];

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

			int[] H = new int[ ARR_LEN ];
			elSubtract( U1, U2, H );

			int[] R = t2;
			elSubtract( S1, S2, R );

			// Check if b == this or b == -this
			if( Nat.isZero( ARR_LEN, H ) )
			{
				if( Nat.isZero( ARR_LEN, R ) )
				{
					// this == b, i.e. this must be doubled
					return this.twice();
				}

				// this == -b, i.e. the result is the point at infinity
				return getInfinity();
			}

			int[] HSquared = new int[ ARR_LEN ];
			elSquare( H, HSquared );

			int[] G = new int[ ARR_LEN ];
			elMultiply( HSquared, H, G );

			int[] V = t3;
			elMultiply( HSquared, U1, V );

			elNegate( G, G );
			Nat.mul( ARR_LEN, S1, G, tt1 );

			c = Nat.addBothTo( ARR_LEN, V, V, G );
			elReduceInt( c, G );

			Element X3 = new Element( t4 );
			elSquare( R, X3.arr );
			elSubtract( X3.arr, G, X3.arr );

			Element Y3 = new Element( G );
			elSubtract( V, X3.arr, Y3.arr );
			elMultiplyAddToExt( Y3.arr, R, tt1 );
			elReduce( tt1, Y3.arr );

			Element Z3 = new Element( H );
			if( !Z1IsOne )
			{
				elMultiply( Z3.arr, Z1.arr, Z3.arr );
			}
			if( !Z2IsOne )
			{
				elMultiply( Z3.arr, Z2.arr, Z3.arr );
			}

			int[] Z3Squared = (Z1IsOne && Z2IsOne) ? HSquared : null;

			Element W3 = calculateJacobianModifiedW( (Element)Z3, Z3Squared );

			ECElement[] zs = new ECElement[] { Z3, W3 };

			return new Point( X3, Y3, zs);
		}

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

			return twiceJacobianModified( true );
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

			return twiceJacobianModified( false ).add( b );
		}


		private Element calculateJacobianModifiedW( Element Z, int[] ZSquared )
		{
			Element a4 = (Element)getA();
			if( Z.isOne() )
			{
				return a4;
			}

			Element W = new Element();
			if( ZSquared == null )
			{
				ZSquared = W.arr;
				elSquare( Z.arr, ZSquared );
			}
			elSquare( ZSquared, W.arr );
			elMultiply( W.arr, a4.arr, W.arr );
			return W;
		}

		private Element getJacobianModifiedW()
		{
			Element W = (Element)this.zs[ 1 ];
			if( W == null )
			{
				// NOTE: Rarely, twicePlus will result in the need for a lazy W1 calculation here
				this.zs[ 1 ] = W = calculateJacobianModifiedW( (Element)this.zs[ 0 ], null );
			}
			return W;
		}

		private Point twiceJacobianModified( boolean calculateW )
		{
			Element X1 = (Element)this.x, Y1 = (Element)this.y,
					Z1 = (Element)this.zs[ 0 ], W1 = getJacobianModifiedW();

			int c;

			int[] M = new int[ ARR_LEN ];
			elSquare( X1.arr, M );
			c = Nat.addBothTo( ARR_LEN, M, M, M );
			c += Nat.addTo( ARR_LEN, W1.arr, M );
			elReduceInt( c, M );

			int[] _2Y1 = new int[ ARR_LEN ];
			elTwice( Y1.arr, _2Y1 );

			int[] _2Y1Squared = new int[ ARR_LEN ];
			elMultiply( _2Y1, Y1.arr, _2Y1Squared );

			int[] S = new int[ ARR_LEN ];
			elMultiply( _2Y1Squared, X1.arr, S );
			elTwice( S, S );

			int[] _8T = new int[ ARR_LEN ];
			elSquare( _2Y1Squared, _8T );
			elTwice( _8T, _8T );

			Element X3 = new Element( _2Y1Squared );
			elSquare( M, X3.arr );
			elSubtract( X3.arr, S, X3.arr );
			elSubtract( X3.arr, S, X3.arr );

			Element Y3 = new Element( S );
			elSubtract( S, X3.arr, Y3.arr );
			elMultiply( Y3.arr, M, Y3.arr );
			elSubtract( Y3.arr, _8T, Y3.arr );

			Element Z3 = new Element( _2Y1 );
			if( !Nat.isOne( ARR_LEN, Z1.arr ) )
			{
				elMultiply( Z3.arr, Z1.arr, Z3.arr );
			}

			Element W3 = null;
			if( calculateW )
			{
				W3 = new Element( _8T );
				elMultiply( W3.arr, W1.arr, W3.arr );
				elTwice( W3.arr, W3.arr );
			}

			return new Point( X3, Y3, new ECElement[] { Z3, W3 } );
		}
	}

	// =================================================================================================================
	// ELEMENT
	// =================================================================================================================

	private class Element extends CustomFpCurve.Element
	{
		private Element( BigInteger X )
		{
			MUST( X != null && (X.signum() >= 0) && (X.compareTo( getP() ) < 0) );

			this.arr = Nat.fromBigInteger( 256, X );
			while( Nat.gte( ARR_LEN, arr, P ) )
			{
				Nat.subFrom( ARR_LEN, P, arr );
			}
		}

		private Element()
		{
			this.arr = new int[ ARR_LEN ];
		}

		protected Element( int[] x )
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

		/**
		 * return a sqrt root - the routine verifies that the calculation returns the right value - if
		 * none exists it returns null.
		 */
		public ECElement sqrt()
		{
			// Q == 8m + 5, so we use Pocklington's method for this case. First, raise this element to
			// the exponent 2^252 - 2^1 (i.e. m + 1) Breaking up the exponent's binary representation
			// into "repunits", we get: { 251 1s } { 1 0s } Therefore we need an addition chain
			// containing 251 (the lengths of the repunits) We use: 1, 2, 3, 4, 7, 11, 15, 30, 60, 120,
			// 131, [251]

			int[] x1 = this.arr;
			if( Nat.isZero( ARR_LEN, x1 ) || Nat.isOne( ARR_LEN, x1 ) )
			{
				return this;
			}

			int[] x2 = new int[ ARR_LEN ];
			elSquare( x1, x2 );
			elMultiply( x2, x1, x2 );
			int[] x3 = x2;
			elSquare( x2, x3 );
			elMultiply( x3, x1, x3 );
			int[] x4 = new int[ ARR_LEN ];
			elSquare( x3, x4 );
			elMultiply( x4, x1, x4 );
			int[] x7 = new int[ ARR_LEN ];
			elSquareN( x4, 3, x7 );
			elMultiply( x7, x3, x7 );
			int[] x11 = x3;
			elSquareN( x7, 4, x11 );
			elMultiply( x11, x4, x11 );
			int[] x15 = x7;
			elSquareN( x11, 4, x15 );
			elMultiply( x15, x4, x15 );
			int[] x30 = x4;
			elSquareN( x15, 15, x30 );
			elMultiply( x30, x15, x30 );
			int[] x60 = x15;
			elSquareN( x30, 30, x60 );
			elMultiply( x60, x30, x60 );
			int[] x120 = x30;
			elSquareN( x60, 60, x120 );
			elMultiply( x120, x60, x120 );
			int[] x131 = x60;
			elSquareN( x120, 11, x131 );
			elMultiply( x131, x11, x131 );
			int[] x251 = x11;
			elSquareN( x131, 120, x251 );
			elMultiply( x251, x120, x251 );

			int[] t1 = x251;
			elSquare( t1, t1 );

			int[] t2 = x120;
			elSquare( t1, t2 );

			if( Arrays.equals( x1, t2 ) )
			{
				return new Element( t1 );
			}

			// If the first guess is incorrect, we multiply by a precomputed power of 2 to get the
			// second guess, which is ((4x)^(m + 1))/2 mod Q
			elMultiply( t1, PRECOMP_POW2, t1 );

			elSquare( t1, t2 );

			if( Arrays.equals( x1, t2 ) )
			{
				return new Element( t1 );
			}

			return null;
		}
	}

	// =================================================================================================================

	@Override
	protected void elReduce( int[] xx, int[] z )
	{
		int xx07 = xx[ 7 ];
		Nat.shiftUpBit( 8, xx, 8, xx07, z, 0 );
		int c = mulByWordAddTo( ARR_LEN, PInv, xx, z ) << 1;
		
		int z7 = z[ 7 ];
		c += (z7 >>> 31) - (xx07 >>> 31);
		z7 &= P7;
		z7 += Nat.addWordTo( 7, c * PInv, z );
		z[ 7 ] = z7;
		if( Nat.gte( ARR_LEN, z, P ) )
		{
			subPFrom( z );
		}
	}

	@Override
	protected void elReduceInt( int x, int[] z )
	{
		int z7 = z[ 7 ];
		int c = (x << 1 | z7 >>> 31);
		z7 &= P7;
		z7 += Nat.addWordTo( 7, c * PInv, z );
		z[ 7 ] = z7;
		if( Nat.gte( ARR_LEN, z, P ) )
		{
			subPFrom( z );
		}
	}

	@Override
	protected void elAdd( int[] x, int[] y, int[] z )
	{
		Nat.add( ARR_LEN, x, y, z );
		if( Nat.gte( ARR_LEN, z, P ) )
		{
			subPFrom( z );
		}
	}

	@Override
	protected void elAddOne( int[] x, int[] z )
	{
		Nat.inc( 8, x, z );
		if( Nat.gte( ARR_LEN, z, P ) )
		{
			subPFrom( z );
		}
	}

	@Override
	protected void elMultiplyAddToExt( int[] x, int[] y, int[] zz )
	{
		Nat.mulAddTo( ARR_LEN, x, y, zz );
		if( Nat.gte( 16, zz, PExt ) )
		{
			subPExtFrom( zz );
		}
	}

	private static int mulByWordAddTo( int len, int x, int[] y, int[] z )
	{
		long c = 0;
		long xVal = x & M;
		
		for( int i = 0; i < len; ++i )
		{
			c += xVal * (z[ i ] & M) + (y[ i ] & M);
			z[ i ] = (int)c;
			c >>>= 32;
		}
		return (int)c;
	}

	@Override
	protected void elSubtract( int[] x, int[] y, int[] z )
	{
		int c = Nat.sub( ARR_LEN, x, y, z );
		if( c != 0 )
		{
			addPTo( z );
		}
	}

	@Override
	protected void elTwice( int[] x, int[] z )
	{
		Nat.shiftUpBit( ARR_LEN, x, 0, z );
		if( Nat.gte( ARR_LEN, z, P ) )
		{
			subPFrom( z );
		}
	}

	private static int addPTo( int[] z )
	{
		long c = (z[ 0 ] & M) - PInv;
		z[ 0 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			c = Nat.decAt( 7, z, 1 );
		}
		c += (z[ 7 ] & M) + ((P7 + 1) & M);
		z[ 7 ] = (int)c;
		c >>= 32;
		return (int)c;
	}

	private static int subPFrom( int[] z )
	{
		long c = (z[ 0 ] & M) + PInv;
		z[ 0 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			c = Nat.incAt( 7, z, 1 );
		}
		c += (z[ 7 ] & M) - ((P7 + 1) & M);
		z[ 7 ] = (int)c;
		c >>= 32;
		return (int)c;
	}

	private static int subPExtFrom( int[] zz )
	{
		long c = (zz[ 0 ] & M) - (PExt[ 0 ] & M);
		zz[ 0 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			c = Nat.decAt( 8, zz, 1 );
		}
		c += (zz[ 8 ] & M) + PInv;
		zz[ 8 ] = (int)c;
		c >>= 32;
		if( c != 0 )
		{
			c = Nat.incAt( 15, zz, 9 );
		}
		c += (zz[ 15 ] & M) - ((PExt[ 15 ] + 1) & M);
		zz[ 15 ] = (int)c;
		c >>= 32;
		return (int)c;
	}

}
