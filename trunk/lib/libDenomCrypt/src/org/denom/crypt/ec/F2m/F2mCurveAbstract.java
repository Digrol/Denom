package org.denom.crypt.ec.F2m;

import java.math.BigInteger;
import java.util.Random;
import org.denom.crypt.ec.*;

import static org.denom.Ex.*;

public abstract class F2mCurveAbstract extends ECCurve
{
	/**
	 * Exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
	 */
	protected final int m;

	/**
	 * TPB: The integer <code>k</code> where <code>x<sup>m</sup> +
	 * x<sup>k</sup> + 1</code> represents the reduction polynomial <code>f(z)</code>.<br>
	 * PPB: The integer <code>k1</code> where <code>x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code> represents the reduction
	 * polynomial <code>f(z)</code>.<br>
	 */
	protected final int k1;

	/**
	 * TPB: Always set to <code>0</code><br>
	 * PPB: The integer <code>k2</code> where <code>x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code> represents the reduction
	 * polynomial <code>f(z)</code>.<br>
	 */
	protected final int k2;

	/**
	 * TPB: Always set to <code>0</code><br>
	 * PPB: The integer <code>k3</code> where <code>x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code> represents the reduction
	 * polynomial <code>f(z)</code>.<br>
	 */
	protected final int k3;
	 
	protected int[] ks;

	protected final boolean isKoblitz;

	// The auxiliary values 's<sub>0</sub>' and 's<sub>1</sub>' used for partial modular reduction for Koblitz curves.
	private BigInteger[] si = null;

	// -----------------------------------------------------------------------------------------------------------------
	protected F2mCurveAbstract( int m, int k1, int k2, int k3, boolean isKoblitz )
	{
		this.m = m;
		this.k1 = k1;
		this.k2 = k2;
		this.k3 = k3;
		this.isKoblitz = isKoblitz;

		if( (k2 == 0) && (k3 == 0) )
		{
			this.ks = new int[] { k1 };
		}
		else
		{
			MUST( k2 < k3, "k2 must be smaller than k3" );
			MUST( k2 > 0, "k2 must be larger than 0" );
			this.ks = new int[] { k1, k2, k3 };
		}
	}

	@Override
	public int getFieldSize()
	{
		return m;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	protected static boolean isKoblitzCurve( BigInteger a, BigInteger b )
	{
		return b.equals( BigInteger.ONE )
			&& (a.equals( BigInteger.ONE ) || a.equals( BigInteger.ZERO ));
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public ECPoint createPoint( BigInteger x, BigInteger y )
	{
		ECElement X = this.fromBigInteger( x );
		ECElement Y = this.fromBigInteger( y );

		if( X.isZero() )
		{
			MUST( Y.square().equals( this.getB() ) );
		}
		else
		{
			// Y becomes Lambda (X + Y/X) here
			Y = Y.divide( X ).add( X );
		}

		return this.createRawPoint( X, Y );
	}

	/**
	 * Decompresses a compressed point P = (xp, yp) (X9.62 s 4.2.2).
	 * 
	 * @param yTilde ~yp, an indication bit for the decompression of yp.
	 * @param X1 The field element xp.
	 * @return the decompressed point.
	 */
	@Override
	protected ECPoint decompressPoint( int yTilde, BigInteger X1 )
	{
		ECElement x = this.fromBigInteger( X1 );
		ECElement y = null;
		if( x.isZero() )
		{
			y = this.getB().sqrt();
		}
		else
		{
			ECElement beta = x.square().invert().multiply( this.getB() ).add( this.getA() ).add( x );
			ECElement z = solveQuadraticEquation( beta );
			if( z != null )
			{
				if( z.testBitZero() != (yTilde == 1) )
				{
					z = z.addOne();
				}

				y = z.add( x );
			}
		}
		MUST( y != null, "Invalid point compression" );

		return this.createRawPoint( x, y );
	}

	/**
	 * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62 D.1.6) The other
	 * solution is <code>z + 1</code>.
	 * 
	 * @param beta The value to solve the quadratic equation for.
	 * @return the solution for <code>z<sup>2</sup> + z = beta</code> or <code>null</code> if no
	 * solution exists.
	 */
	protected ECElement solveQuadraticEquation( ECElement beta )
	{
		if( beta.isZero() )
		{
			return beta;
		}

		ECElement gamma, z, zeroElement = this.fromBigInteger( BigInteger.ZERO );

		int m = this.getFieldSize();
		Random rand = new Random();
		do
		{
			ECElement t = this.fromBigInteger( new BigInteger( m, rand ) );
			z = zeroElement;
			ECElement w = beta;
			for( int i = 1; i < m; i++ )
			{
				ECElement w2 = w.square();
				z = z.square().add( w2.multiply( t ) );
				w = w2.add( beta );
			}
			if( !w.isZero() )
			{
				return null;
			}
			gamma = z.square().add( z );
		}
		while( gamma.isZero() );

		return z;
	}

	/**
	 * @return the auxiliary values <code>s<sub>0</sub></code> and <code>s<sub>1</sub></code>
	 * used for partial modular reduction for Koblitz curves.
	 */
	protected BigInteger[] getSi()
	{
		if( si != null )
		{
			return si;
		}

		MUST( isKoblitz, "si is defined for Koblitz curves only" );

		int m = getFieldSize();
		int a = getA().toBigInteger().intValue();

		byte mu = getMu( a );

		int shifts = 0;
		if( getCofactor().equals( BigInteger.valueOf( 2 ) ) )
		{
			shifts = 1;
		}
		if( getCofactor().equals( BigInteger.valueOf( 4 ) ) )
		{
			shifts = 2;
		}

		int index = m + 3 - a;
		BigInteger[] ui = getLucas( mu, index, false );
		if( mu == 1 )
		{
			ui[ 0 ] = ui[ 0 ].negate();
			ui[ 1 ] = ui[ 1 ].negate();
		}

		BigInteger dividend0 = BigInteger.ONE.add( ui[ 1 ] ).shiftRight( shifts );
		BigInteger dividend1 = BigInteger.ONE.add( ui[ 0 ] ).shiftRight( shifts ).negate();

		si = new BigInteger[] { dividend0, dividend1 };
		return si;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public ECPoint sumOfTwoMultiplies( ECPoint P, BigInteger a, ECPoint Q, BigInteger b )
	{
		if( isKoblitz )
		{
			// Point multiplication for Koblitz curves (using WTNAF) beats Shamir's trick
			Q = importPoint( Q );
			return P.multiply( a ).add( Q.multiply( b ) );
		}
		return super.sumOfTwoMultiplies( P, a, Q, b );
	}


	// =================================================================================================================
	// POINT
	// =================================================================================================================

	protected abstract class F2mPointAbstract extends ECPoint
	{
		protected F2mPointAbstract( ECElement x, ECElement y )
		{
			super( x, y, new ECElement[]{ fromBigInteger( BigInteger.ONE ) } );
		}

		protected F2mPointAbstract( ECElement x, ECElement y, ECElement[] zs )
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
			return createRawPoint( this.x.multiply( zInv ), this.y.multiply( zInv ) );
		}


		@Override
		protected boolean satisfiesCurveEquation()
		{
			ECElement X = this.x, A = getA(), B = getB();

			ECElement Z = this.zs[ 0 ];
			boolean ZIsOne = Z.isOne();

			if( X.isZero() )
			{
				// NOTE: For x == 0, we expect the affine-y instead of the lambda-y 
				ECElement Y = this.y;
				ECElement lhs = Y.square(), rhs = B;
				if( !ZIsOne )
				{
					rhs = rhs.multiply( Z.square() );
				}
				return lhs.equals( rhs );
			}

			ECElement L = this.y, X2 = X.square();
			ECElement lhs, rhs;
			if( ZIsOne )
			{
				lhs = L.square().add( L ).add( A );
				rhs = X2.square().add( B );
			}
			else
			{
				ECElement Z2 = Z.square(), Z4 = Z2.square();
				lhs = L.add( Z ).multiplyPlusProduct( L, A, Z2 );
				rhs = X2.squarePlusProduct( B, Z4 );
			}
			lhs = lhs.multiply( X2 );
			return lhs.equals( rhs );
		}

		@Override
		protected boolean satisfiesOrder()
		{
			BigInteger cofactor = getCofactor();
			if( cofactor.equals( BigInteger.valueOf( 2 ) ) )
			{
				// Check that the trace of (X + A) is 0, then there exists a solution to L^2 + L = X + A,
				// and so a halving is possible, so this point is the double of another.
				ECPoint N = this.normalize();
				ECElement X = N.getAffineXCoord();
				ECElement rhs = X.add( getA() );
				return ((F2mElementAbstract)rhs).trace() == 0;
			}
			if( cofactor.equals( BigInteger.valueOf( 4 ) ) )
			{
				// Solve L^2 + L = X + A to find the half of this point, if it exists (fail if not).
				// Generate both possibilities for the square of the half-point's x-coordinate (w),
				// and check if Tr(w + A) == 0 for at least one; then a second halving is possible
				// (see comments for cofactor 2 above), so this point is four times another. Note: Tr(x^2) == Tr(x).
				ECPoint N = this.normalize();
				ECElement X = N.getAffineXCoord();
				ECElement lambda = solveQuadraticEquation( X.add( getA() ) );
				if( lambda == null )
				{
					return false;
				}
				ECElement w = X.multiply( lambda ).add( N.getAffineYCoord() );
				ECElement t = w.add( getA() );
				return (((F2mElementAbstract)t).trace() == 0) || (((F2mElementAbstract)t.add( X )).trace() == 0);
			}

			return super.satisfiesOrder();
		}


		@Override
		public final ECPoint multiply( BigInteger k )
		{
			if( isKoblitz )
			{
				return multiplyWTau( k );
			}
			return super.multiply( k );
		}

		// =============================================================================================================

		private F2mPointAbstract[] preCompTauWNaf = null;

		// -----------------------------------------------------------------------------------------------------------------
		private void precomputeTNaf( byte a )
		{
			if( preCompTauWNaf != null )
				return;

			byte[][] alphaTnaf = (a == 0) ? alpha0Tnaf : alpha1Tnaf;

			preCompTauWNaf = new F2mPointAbstract[ (alphaTnaf.length + 1) >>> 1 ];
			preCompTauWNaf[ 0 ] = (F2mPointAbstract)normalize();

			int precompLen = alphaTnaf.length;
			for( int i = 3; i < precompLen; i += 2 )
			{
				preCompTauWNaf[ i >>> 1 ] = (F2mPointAbstract)multiplyFromTnaf( alphaTnaf[ i ] ).normalize();
			}
		}

		// -----------------------------------------------------------------------------------------------------------------
		private F2mPointAbstract tauPow( int pow )
		{
			if( isInfinity() )
			{
				return this;
			}

			ECElement X1 = this.x;
			ECElement Y1 = this.y;
			ECElement Z1 = this.zs[ 0 ];
			return (F2mPointAbstract)createRawPoint( X1.squarePow( pow ), Y1.squarePow( pow ), new ECElement[] { Z1.squarePow( pow ) } );
		}

		/**
		 * Point multiplication based on the window &tau;-adic nonadjacent form (WTNAF).
		 * Based on the paper "Improved Algorithms for Arithmetic on Anomalous Binary Curves" by Jerome A. Solinas.
		 * The paper first appeared in the Proceedings of Crypto 1997.
		 */
		private ECPoint multiplyWTau( BigInteger k )
		{
			int sign = k.signum();
			if( sign == 0 || isInfinity() )
			{
				return getInfinity();
			}
			k = k.abs();

			int m = getFieldSize();
			byte a = getA().toBigInteger().byteValue();
			byte mu = getMu( a );

			ZTauElement rho = partModReduction( k, m, a, getSi(), mu );

			ZTauElement[] alpha = (a == 0) ? alpha0 : alpha1;
			BigInteger tw = getTw( mu, WIDTH );
			byte[] u = tauAdicWNaf( mu, rho, WIDTH, BigInteger.valueOf( POW_2_WIDTH ), tw, alpha );

			precomputeTNaf( a );

			F2mPointAbstract[] puNeg = new F2mPointAbstract[ preCompTauWNaf.length ];
			for( int i = 0; i < preCompTauWNaf.length; ++i )
			{
				puNeg[ i ] = (F2mPointAbstract)preCompTauWNaf[ i ].negate();
			}

			// q = infinity
			F2mPointAbstract q = (F2mPointAbstract)getInfinity();

			int tauCount = 0;
			for( int i = u.length - 1; i >= 0; i-- )
			{
				++tauCount;
				int ui = u[ i ];
				if( ui != 0 )
				{
					q = q.tauPow( tauCount );
					tauCount = 0;

					ECPoint x = ui > 0 ? preCompTauWNaf[ ui >>> 1 ] : puNeg[ (-ui) >>> 1 ];
					q = (F2mPointAbstract)q.add( x );
				}
			}
			if( tauCount > 0 )
			{
				q = q.tauPow( tauCount );
			}

			return (sign > 0) ? q : q.negate();
		}


		/**
		 * Multiplies a {@link org.denom.crypt.ec.F2mPointAbstract AbstractF2m} by an element
		 * <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code> using the <code>&tau;</code>-adic NAF
		 * (TNAF) method, given the TNAF of <code>&lambda;</code>.
		 * @param p The AbstractF2m to multiply.
		 * @param u The the TNAF of <code>&lambda;</code>..
		 * @return <code>&lambda; * p</code>
		 */
		private F2mPointAbstract multiplyFromTnaf( byte[] u )
		{
			F2mPointAbstract q = (F2mPointAbstract)getInfinity();
			F2mPointAbstract pNeg = (F2mPointAbstract)negate();
			int tauCount = 0;
			for( int i = u.length - 1; i >= 0; i-- )
			{
				++tauCount;
				byte ui = u[ i ];
				if( ui != 0 )
				{
					q = q.tauPow( tauCount );
					tauCount = 0;

					ECPoint x = ui > 0 ? this : pNeg;
					q = (F2mPointAbstract)q.add( x );
				}
			}
			if( tauCount > 0 )
			{
				q = q.tauPow( tauCount );
			}
			return q;
		}

	} // Point

	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	private static final BigInteger MINUS_ONE = BigInteger.valueOf( -1 );
	private static final BigInteger MINUS_THREE = BigInteger.valueOf( -3 );

	/**
	 * The window width of WTNAF. The standard value of 4 is slightly less than optimal for running
	 * time, but keeps space requirements for precomputation low. For typical curves, a value of 5
	 * or 6 results in a better running time. When changing this value, the
	 * <code>&alpha;<sub>u</sub></code>'s must be computed differently, see e.g. "Guide to Elliptic
	 * Curve Cryptography", Darrel Hankerson, Alfred Menezes, Scott Vanstone, Springer-Verlag New
	 * York Inc., 2004, p. 121-122
	 */
	private static final byte WIDTH = 4;

	/**
	 * 2<sup>4</sup>
	 */
	private static final byte POW_2_WIDTH = 16;

	/**
	 * The <code>&alpha;<sub>u</sub></code>'s for <code>a=0</code> as an array of
	 * <code>ZTauElement</code>s.
	 */
	private static final ZTauElement[] alpha0 = {
		null,
		new ZTauElement( BigInteger.ONE, BigInteger.ZERO ),
		null,
		new ZTauElement( MINUS_THREE, MINUS_ONE ),
		null,
		new ZTauElement( MINUS_ONE, MINUS_ONE ),
		null,
		new ZTauElement( BigInteger.ONE, MINUS_ONE ),
		null };

	/**
	 * The <code>&alpha;<sub>u</sub></code>'s for <code>a=0</code> as an array of TNAFs.
	 */
	private static final byte[][] alpha0Tnaf = { null, { 1 }, null, { -1, 0, 1 }, null, { 1, 0, 1 }, null, { -1, 0, 0, 1 } };

	/**
	 * The <code>&alpha;<sub>u</sub></code>'s for <code>a=1</code> as an array of
	 * <code>ZTauElement</code>s.
	 */
	private static final ZTauElement[] alpha1 = {
		null,
		new ZTauElement( BigInteger.ONE, BigInteger.ZERO ),
		null,
		new ZTauElement( MINUS_THREE, BigInteger.ONE ),
		null,
		new ZTauElement( MINUS_ONE, BigInteger.ONE ),
		null,
		new ZTauElement( BigInteger.ONE, BigInteger.ONE ),
		null };

	/**
	 * The <code>&alpha;<sub>u</sub></code>'s for <code>a=1</code> as an array of TNAFs.
	 */
	private static final byte[][] alpha1Tnaf = { null, { 1 }, null, { -1, 0, 1 }, null, { 1, 0, 1 }, null, { -1, 0, 0, -1 } };

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Element of '<b>Z</b>[&tau;]'. Let &lambda; be an element of '<b>Z</b>[&tau;]'.
	 * Then &lambda; is given as  '&lambda; = u + v&tau;'.
	 */
	private static class ZTauElement
	{
		private final BigInteger u; // The 'real' part of &lambda;
		private final BigInteger v; // '&tau;-adic' part of &lambda;

		private ZTauElement( BigInteger u, BigInteger v )
		{
			this.u = u;
			this.v = v;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static byte getMu( int curveA )
	{
		return (byte)(curveA == 0 ? -1 : 1);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Computes the auxiliary value <code>t<sub>w</sub></code>. If the width is 4, then for
	 * <code>mu = 1</code>, <code>t<sub>w</sub> = 6</code> and for <code>mu = -1</code>,
	 * <code>t<sub>w</sub> = 10</code>
	 * @param mu The parameter <code>&mu;</code> of the elliptic curve.
	 * @param w The window width of the WTNAF.
	 * @return the auxiliary value <code>t<sub>w</sub></code>
	 */
	private BigInteger getTw( byte mu, int w )
	{
		if( w == 4 )
		{
			if( mu == 1 )
			{
				return BigInteger.valueOf( 6 );
			}
			else
			{
				// mu == -1
				return BigInteger.valueOf( 10 );
			}
		}
		else
		{
			// For w <> 4, the values must be computed
			BigInteger[] us = getLucas( mu, w, false );
			BigInteger twoToW = BigInteger.ZERO.setBit( w );
			BigInteger u1invert = us[ 1 ].modInverse( twoToW );
			BigInteger tw;
			tw = BigInteger.valueOf( 2 ).multiply( us[ 0 ] ).multiply( u1invert ).mod( twoToW );
			return tw;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Calculates the Lucas Sequence elements <code>U<sub>k-1</sub></code> and
	 * <code>U<sub>k</sub></code> or <code>V<sub>k-1</sub></code> and <code>V<sub>k</sub></code>.
	 * @param mu The parameter <code>&mu;</code> of the elliptic curve.
	 * @param k The index of the second element of the Lucas Sequence to be returned.
	 * @param doV If set to true, computes <code>V<sub>k-1</sub></code> and
	 * <code>V<sub>k</sub></code>, otherwise <code>U<sub>k-1</sub></code> and
	 * <code>U<sub>k</sub></code>.
	 * @return An array with 2 elements, containing <code>U<sub>k-1</sub></code> and
	 * <code>U<sub>k</sub></code> or <code>V<sub>k-1</sub></code> and <code>V<sub>k</sub></code>.
	 */
	private BigInteger[] getLucas( byte mu, int k, boolean doV )
	{
		MUST( (mu == 1) || (mu == -1), "mu must be 1 or -1" );

		BigInteger u0;
		BigInteger u1;
		BigInteger u2;

		if( doV )
		{
			u0 = BigInteger.valueOf( 2 );
			u1 = BigInteger.valueOf( mu );
		}
		else
		{
			u0 = BigInteger.ZERO;
			u1 = BigInteger.ONE;
		}

		for( int i = 1; i < k; i++ )
		{
			// u2 = mu*u1 - 2*u0;
			BigInteger s = null;
			if( mu == 1 )
			{
				s = u1;
			}
			else
			{
				// mu == -1
				s = u1.negate();
			}

			u2 = s.subtract( u0.shiftLeft( 1 ) );
			u0 = u1;
			u1 = u2;
		}

		BigInteger[] retVal = { u0, u1 };
		return retVal;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Approximate division by <code>n</code>. For an integer <code>k</code>, the value
	 * <code>&lambda; = s k / n</code> is computed to <code>c</code> bits of accuracy.
	 * @param k The parameter <code>k</code>.
	 * @param s The curve parameter <code>s<sub>0</sub></code> or <code>s<sub>1</sub></code>.
	 * @param vm The Lucas Sequence element <code>V<sub>m</sub></code>.
	 * @param a The parameter <code>a</code> of the elliptic curve.
	 * @param m The bit length of the finite field <code><b>F</b><sub>m</sub></code>.
	 * @param c The number of bits of accuracy, i.e. the scale of the returned
	 * <code>SimpleBigDecimal</code>.
	 * @return The value <code>&lambda; = s k / n</code> computed to <code>c</code> bits of
	 * accuracy.
	 */
	private SimpleBigDecimal approximateDivisionByN( BigInteger k, BigInteger s, BigInteger vm, byte a, int m, int c )
	{
		int _k = (m + 5) / 2 + c;
		BigInteger ns = k.shiftRight( m - _k - 2 + a );

		BigInteger gs = s.multiply( ns );

		BigInteger hs = gs.shiftRight( m );

		BigInteger js = vm.multiply( hs );

		BigInteger gsPlusJs = gs.add( js );
		BigInteger ls = gsPlusJs.shiftRight( _k - c );
		if( gsPlusJs.testBit( _k - c - 1 ) )
		{
			// round up
			ls = ls.add( BigInteger.ONE );
		}

		return new SimpleBigDecimal( ls, c );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Rounds an element <code>&lambda;</code> of <code><b>R</b>[&tau;]</code> to an element of
	 * <code><b>Z</b>[&tau;]</code>, such that their difference has minimal norm.
	 * <code>&lambda;</code> is given as
	 * <code>&lambda; = &lambda;<sub>0</sub> + &lambda;<sub>1</sub>&tau;</code>.
	 * @param lambda0 The component <code>&lambda;<sub>0</sub></code>.
	 * @param lambda1 The component <code>&lambda;<sub>1</sub></code>.
	 * @param mu The parameter <code>&mu;</code> of the elliptic curve. Must equal 1 or -1.
	 * @return The rounded element of <code><b>Z</b>[&tau;]</code>.
	 * @throws IllegalArgumentException if <code>lambda0</code> and <code>lambda1</code> do not have
	 * same scale.
	 */
	private ZTauElement round( SimpleBigDecimal lambda0, SimpleBigDecimal lambda1, byte mu )
	{
		int scale = lambda0.scale;
		MUST( lambda1.scale == scale );
		MUST( (mu == 1) || (mu == -1) );

		BigInteger f0 = lambda0.round();
		BigInteger f1 = lambda1.round();

		SimpleBigDecimal eta0 = lambda0.subtract( f0 );
		SimpleBigDecimal eta1 = lambda1.subtract( f1 );

		// eta = 2*eta0 + mu*eta1
		SimpleBigDecimal eta = eta0.add( eta0 );
		if( mu == 1 )
		{
			eta = eta.add( eta1 );
		}
		else
		{
			// mu == -1
			eta = eta.subtract( eta1 );
		}

		// check1 = eta0 - 3*mu*eta1
		// check2 = eta0 + 4*mu*eta1
		SimpleBigDecimal threeEta1 = eta1.add( eta1 ).add( eta1 );
		SimpleBigDecimal fourEta1 = threeEta1.add( eta1 );
		SimpleBigDecimal check1;
		SimpleBigDecimal check2;
		if( mu == 1 )
		{
			check1 = eta0.subtract( threeEta1 );
			check2 = eta0.add( fourEta1 );
		}
		else
		{
			// mu == -1
			check1 = eta0.add( threeEta1 );
			check2 = eta0.subtract( fourEta1 );
		}

		byte h0 = 0;
		byte h1 = 0;

		// if eta >= 1
		if( eta.compareTo( BigInteger.ONE ) >= 0 )
		{
			if( check1.compareTo( MINUS_ONE ) < 0 )
			{
				h1 = mu;
			}
			else
			{
				h0 = 1;
			}
		}
		else
		{
			// eta < 1
			if( check2.compareTo( BigInteger.valueOf( 2 ) ) >= 0 )
			{
				h1 = mu;
			}
		}

		// if eta < -1
		if( eta.compareTo( MINUS_ONE ) < 0 )
		{
			if( check1.compareTo( BigInteger.ONE ) >= 0 )
			{
				h1 = (byte)-mu;
			}
			else
			{
				h0 = -1;
			}
		}
		else
		{
			// eta >= -1
			if( check2.compareTo( BigInteger.valueOf( -2 ) ) < 0 )
			{
				h1 = (byte)-mu;
			}
		}

		BigInteger q0 = f0.add( BigInteger.valueOf( h0 ) );
		BigInteger q1 = f1.add( BigInteger.valueOf( h1 ) );
		return new ZTauElement( q0, q1 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Partial modular reduction modulo <code>(&tau;<sup>m</sup> - 1)/(&tau; - 1)</code>.
	 * @param k The integer to be reduced.
	 * @param m The bitlength of the underlying finite field.
	 * @param a The parameter <code>a</code> of the elliptic curve.
	 * @param s The auxiliary values <code>s<sub>0</sub></code> and <code>s<sub>1</sub></code>.
	 * @param mu The parameter &mu; of the elliptic curve.
	 * @param c The precision (number of bits of accuracy) of the partial modular reduction.
	 * @return <code>&rho; := k partmod (&tau;<sup>m</sup> - 1)/(&tau; - 1)</code>
	 */
	private ZTauElement partModReduction( BigInteger k, int m, byte a, BigInteger[] s, byte mu )
	{
		// d0 = s[0] + mu*s[1]; mu is either 1 or -1
		BigInteger d0;
		if( mu == 1 )
		{
			d0 = s[ 0 ].add( s[ 1 ] );
		}
		else
		{
			d0 = s[ 0 ].subtract( s[ 1 ] );
		}

		BigInteger[] v = getLucas( mu, m, true );
		BigInteger vm = v[ 1 ];

		SimpleBigDecimal lambda0 = approximateDivisionByN( k, s[ 0 ], vm, a, m, 10 );
		SimpleBigDecimal lambda1 = approximateDivisionByN( k, s[ 1 ], vm, a, m, 10 );

		ZTauElement q = round( lambda0, lambda1, mu );

		// r0 = n - d0*q0 - 2*s1*q1
		BigInteger r0 = k.subtract( d0.multiply( q.u ) ).subtract( BigInteger.valueOf( 2 ).multiply( s[ 1 ] ).multiply( q.v ) );

		// r1 = s1*q0 - s0*q1
		BigInteger r1 = s[ 1 ].multiply( q.u ).subtract( s[ 0 ].multiply( q.v ) );

		return new ZTauElement( r0, r1 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Computes the norm of an element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code>.
	 * @param mu The parameter <code>&mu;</code> of the elliptic curve.
	 * @param lambda The element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code>.
	 * @return The norm of <code>&lambda;</code>.
	 */
	private BigInteger norm( final byte mu, ZTauElement lambda )
	{
		BigInteger norm;

		// s1 = u^2
		BigInteger s1 = lambda.u.multiply( lambda.u );

		// s2 = u * v
		BigInteger s2 = lambda.u.multiply( lambda.v );

		// s3 = 2 * v^2
		BigInteger s3 = lambda.v.multiply( lambda.v ).shiftLeft( 1 );

		if( mu == 1 )
		{
			norm = s1.add( s2 ).add( s3 );
		}
		else if( mu == -1 )
		{
			norm = s1.subtract( s2 ).add( s3 );
		}
		else
		{
			throw new IllegalArgumentException( "mu must be 1 or -1" );
		}

		return norm;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Computes the <code>[&tau;]</code>-adic window NAF of an element <code>&lambda;</code> of
	 * <code><b>Z</b>[&tau;]</code>.
	 * @param mu The parameter &mu; of the elliptic curve.
	 * @param lambda The element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code> of which to
	 * compute the <code>[&tau;]</code>-adic NAF.
	 * @param width The window width of the resulting WNAF.
	 * @param pow2w 2<sup>width</sup>.
	 * @param tw The auxiliary value <code>t<sub>w</sub></code>.
	 * @param alpha The <code>&alpha;<sub>u</sub></code>'s for the window width.
	 * @return The <code>[&tau;]</code>-adic window NAF of <code>&lambda;</code>.
	 */
	private byte[] tauAdicWNaf( byte mu, ZTauElement lambda, byte width, BigInteger pow2w, BigInteger tw, ZTauElement[] alpha )
	{
		if( !((mu == 1) || (mu == -1)) )
		{
			throw new IllegalArgumentException( "mu must be 1 or -1" );
		}

		BigInteger norm = norm( mu, lambda );

		// Ceiling of log2 of the norm 
		int log2Norm = norm.bitLength();

		// If length(TNAF) > 30, then length(TNAF) < log2Norm + 3.52
		int maxLength = log2Norm > 30 ? log2Norm + 4 + width : 34 + width;

		// The array holding the TNAF
		byte[] u = new byte[ maxLength ];

		// 2^(width - 1)
		BigInteger pow2wMin1 = pow2w.shiftRight( 1 );

		// Split lambda into two BigIntegers to simplify calculations
		BigInteger r0 = lambda.u;
		BigInteger r1 = lambda.v;
		int i = 0;

		// while lambda <> (0, 0)
		while( !((r0.equals( BigInteger.ZERO )) && (r1.equals( BigInteger.ZERO ))) )
		{
			// if r0 is odd
			if( r0.testBit( 0 ) )
			{
				// uUnMod = r0 + r1*tw mod 2^width
				BigInteger uUnMod = r0.add( r1.multiply( tw ) ).mod( pow2w );

				byte uLocal;
				// if uUnMod >= 2^(width - 1)
				if( uUnMod.compareTo( pow2wMin1 ) >= 0 )
				{
					uLocal = (byte)uUnMod.subtract( pow2w ).intValue();
				}
				else
				{
					uLocal = (byte)uUnMod.intValue();
				}
				// uLocal is now in [-2^(width-1), 2^(width-1)-1]

				u[ i ] = uLocal;
				boolean s = true;
				if( uLocal < 0 )
				{
					s = false;
					uLocal = (byte)-uLocal;
				}
				// uLocal is now >= 0

				if( s )
				{
					r0 = r0.subtract( alpha[ uLocal ].u );
					r1 = r1.subtract( alpha[ uLocal ].v );
				}
				else
				{
					r0 = r0.add( alpha[ uLocal ].u );
					r1 = r1.add( alpha[ uLocal ].v );
				}
			}
			else
			{
				u[ i ] = 0;
			}

			BigInteger t = r0;

			if( mu == 1 )
			{
				r0 = r1.add( r0.shiftRight( 1 ) );
			}
			else
			{
				// mu == -1
				r0 = r1.subtract( r0.shiftRight( 1 ) );
			}
			r1 = t.shiftRight( 1 ).negate();
			i++;
		}
		return u;
	}

	// =================================================================================================================
	// ELEMENT
	// =================================================================================================================

	protected abstract class F2mElementAbstract extends ECElement
	{
		protected F2mElementAbstract() {}

		@Override
		public final int getFieldSize()
		{
			return F2mCurveAbstract.this.getFieldSize();
		}

		protected int trace()
		{
			int m = getFieldSize();
			ECElement fe = this;
			ECElement tr = fe;
			for( int i = 1; i < m; ++i )
			{
				fe = fe.square();
				tr = tr.add( fe );
			}
			if( tr.isZero() )
			{
				return 0;
			}
			if( tr.isOne() )
			{
				return 1;
			}
			THROW( "Internal error in trace calculation" );
			return 0;
		}

	}
	
}
