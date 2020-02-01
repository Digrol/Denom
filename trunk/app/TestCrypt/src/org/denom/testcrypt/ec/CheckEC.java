package org.denom.testcrypt.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.denom.*;
import org.denom.log.Colors;
import org.denom.log.ILog;
import org.denom.crypt.hash.SHA256;
import org.denom.crypt.ec.*;
import org.denom.crypt.ec.F2m.F2mCurveAbstract;
import org.denom.crypt.ec.Fp.FpCurveAbstract;
import org.denom.crypt.ec.ECCurve.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

class CheckEC
{
	private static final SecureRandom RAND = new SecureRandom();

	// -----------------------------------------------------------------------------------------------------------------
	private static void checkCurveMath( ECCurve curve )
	{
		BigInteger order = curve.getOrder();
		MUST( curve.getG().isValid() );

		ECPoint p = curve.GMul( new BigInteger( order.bitLength(), RAND ) ).normalize();
		ECPoint infinity = curve.getInfinity();


		// Add, Subsract
		MUST( p.twice().equals(  p.add( p )  ) );
		MUST( p.equals(  p.twice().subtract( p )  ) );
		MUST( p.equals(  p.twicePlus( p.negate() )  ) );
		MUST( infinity.equals(  p.subtract( p )  ) );
		MUST( p.equals(  p.add( infinity )  ) );
		MUST( p.equals(  infinity.add( p )  ) );
		MUST( infinity.equals(  infinity.add( infinity )  ) );
		MUST( infinity.equals(  infinity.twice()  ) );


		// Multiply Point
		BigInteger k = new BigInteger( order.bitLength(), RAND );
		MUST( p.referenceMultiply( k ).equals(  p.multiply( k )  ) );
		MUST( infinity.referenceMultiply( k ).equals(  infinity.multiply( k )  ) );

		for( int i = 0; i < 5; ++i )
		{
			k = new BigInteger( order.bitLength(), RAND );
			ECPoint pA = curve.GMul( k );
			MUST( curve.getG().referenceMultiply( k ).equals( pA ) );
		}


		// Encode - decode points
		for( int i = 0; i < 5; ++i )
		{
			MUST( p.equals( curve.decodePoint( p.getEncoded( false ) ) ) );
			MUST( p.equals( curve.decodePoint( p.getEncoded( true ) ) ) );
			p = p.twice();
		}


		// Sum of 2 multiplies
		int bitLen = order.bitLength();
		p = curve.GMul( new BigInteger( bitLen, RAND ) );
		BigInteger a = new BigInteger( bitLen, RAND );

		for( int i = 0; i < 4; ++i )
		{
			ECPoint q = curve.GMul( new BigInteger( bitLen, RAND ) );
			BigInteger b = new BigInteger( bitLen, RAND );

			ECPoint u = p.multiply( a ).add( q.multiply( b ) );
			ECPoint w = curve.sumOfTwoMultiplies( p, a, q, b );
			MUST( u.normalize().equals( w.normalize() ) );

			p = q;
			a = b;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Return a random BigInteger not less than 'min' and not greater than 'max'
	 * 
	 * @param min the least value that may be generated
	 * @param max the greatest value that may be generated
	 * @param random the source of randomness
	 * @return a random BigInteger value in the range [min,max]
	 */
	private static BigInteger createRandomInRange( BigInteger min, BigInteger max, SecureRandom random )
	{
		int cmp = min.compareTo( max );
		if( cmp >= 0 )
		{
			MUST( cmp <= 0, "'min' may not be greater than 'max'" );
			return min;
		}

		if( min.bitLength() > max.bitLength() / 2 )
		{
			return createRandomInRange( BigInteger.valueOf( 0 ), max.subtract( min ), random ).add( min );
		}

		for( int i = 0; i < 1000; ++i )
		{
			BigInteger x = new BigInteger( max.bitLength(), random );
			if( x.compareTo( min ) >= 0 && x.compareTo( max ) <= 0 )
			{
				return x;
			}
		}

		// fall back to a faster (restricted) method
		return new BigInteger( max.subtract( min ).bitLength() - 1, random ).add( min );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void curveFpMath( FpCurveAbstract curve )
	{
		checkCurveMath( curve );

		// SQRT
		BigInteger P = curve.getP();
		BigInteger pMinusOne = P.subtract( BigInteger.valueOf( 1 ) );
		BigInteger legendreExponent = P.shiftRight( 1 );

		int count = 0;
		while( count < 10 )
		{
			BigInteger nonSquare = createRandomInRange( BigInteger.valueOf( 2 ), pMinusOne, RAND );
			if( !nonSquare.modPow( legendreExponent, P ).equals( BigInteger.valueOf( 1 ) ) )
			{
				ECElement root = curve.fromBigInteger( nonSquare ).sqrt();
				MUST( root == null );
				++count;
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void curveF2mMath( F2mCurveAbstract curve )
	{
		checkCurveMath( curve );

		// SQRT
		int m = curve.getFieldSize();
		BigInteger x = new BigInteger( m, RAND );
		ECElement fe = curve.fromBigInteger( x );
		for( int i = 0; i < 100; ++i )
		{
			ECElement sq = fe.square();
			ECElement check = sq.sqrt();
			MUST( fe.equals( check ) );
			fe = sq;
		}

		BigInteger h = curve.getCofactor();
		if( (h != null) && (h.compareTo( BigInteger.valueOf( 1 ) ) > 0) )
		{
			ECPoint order2 = curve.createPoint( BigInteger.valueOf( 0 ), curve.getB().sqrt().toBigInteger() );
			ECPoint bad = curve.getG().add( order2 );
			MUST( !bad.isValid() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void fixedSign( ECCurve curve, String privateD, String publicQ, String msg, String fixedK, String fixedSign )
	{
		ECDSA ecdsa = new ECDSA( curve ).setPrivate( Bin(privateD) ).setPublic( Bin(publicQ) );
		ecdsa.setFixedK( Bin(fixedK) );
		Binary sign = ecdsa.sign( Bin(msg) );
		MUST( sign.equals( fixedSign ), "Wrong sign" );
		MUST( ecdsa.verify( Bin(msg), sign ), "Wrong verify" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void cross( ILog log, String curveName,  ECCurve commonCurve,  ECCurve customCurve, int signsNumber )
	{
		ECDSA std = new ECDSA( commonCurve );
		ECDSA custom = new ECDSA( customCurve );
		crossSign( log, curveName, std, custom, signsNumber );
		measureCrossSigns( log, curveName, std, custom, signsNumber );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void crossSign( ILog log, String curveName, ECDSA std, ECDSA custom, int signsNumber )
	{
		log.write( "Cross check " );
		log.write( 0xFFFFA0A0, curveName );
		log.write(" ... " );

		for(int i = 0; i < signsNumber; ++i )
		{
			Binary hash = Bin().random( 32 );
			std.generateKeyPair();
			custom.setPrivate( std.getPrivate() ).setPublic( std.getPublic() );

			Binary sign = std.sign( hash );
			MUST( std.verify( hash, sign ) );
			MUST( custom.verify( hash, sign ) );

			custom.generateKeyPair();
			std.setPrivate( custom.getPrivate() ).setPublic( custom.getPublic() );

			sign = custom.sign( hash );
			MUST( custom.verify( hash, sign ) );
			MUST( std.verify( hash, sign ) );
		}
		log.writeln( Colors.GREEN_I, "OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static String pad( String text, int len )
	{
		return Strings.PadLeft( text, len, ' ' );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void measureAlg( ILog log, String name, ECDSA alg, int signsNumber )
	{
		Binary hash = new SHA256().calc( Bin().random( 32 ) );

		log.write( Colors.KEY, pad( name, 8 ) );
		long t = Ticker.measureMs( signsNumber, () -> alg.generateKeyPair() );
		log.write( Colors.CYAN_I, pad("" + t, 8) );

		t = Ticker.measureMs( signsNumber, () -> alg.sign( hash ) );
		log.write( Colors.CYAN_I, pad("" + t, 8) );
		
		Binary sign = alg.sign( hash ); 
		t = Ticker.measureMs( signsNumber, () -> alg.verify( hash, sign ) );
		log.writeln( Colors.CYAN_I, pad("" + t, 8) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void measureCurve( ILog log, String curveName, ECCurve curve, int signsNumber )
	{
		log.write( "Measure " );
		log.write( 0xFFFFA0A0, curveName );
		log.writeln(" (" + signsNumber + "):" );
		log.writeln( 0xFFFF80FF, "        generate    sign  verify" );
		measureAlg( log, "", new ECDSA( curve ), signsNumber );
		log.writeln( Colors.DARK_GRAY, "--------------------------------" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void measureCrossSigns( ILog log, String curveName, ECDSA common, ECDSA custom, int signsNumber )
	{
		log.write( "Measure " );
		log.write( 0xFFFFA0A0, curveName );
		log.writeln(" (" + signsNumber + "):" );
		log.writeln( 0xFFFF80FF, "        generate    sign  verify" );
		measureAlg( log, "Common", common, signsNumber );
		measureAlg( log, "Custom", custom, signsNumber );
		log.writeln( Colors.DARK_GRAY, "--------------------------------" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Goes through all points on an elliptic curve and checks, if adding a point 'k'-times
	 * is the same as multiplying the point by 'k', for all 'k'.
	 * Should be called for points on very small elliptic curves only.
	 */
	static void checkAllPoints( ECPoint p, ECPoint infinity )
	{
		ECPoint adder = infinity;
		BigInteger i = BigInteger.valueOf( 1 );
		do
		{
			adder = adder.add( p );
			MUST( adder.equals(  p.multiply( i )  ) );
			i = i.add( BigInteger.ONE );
		}
		while( !(adder.equals( infinity )) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Checks, if the point multiplication algorithm of the given point yields the same result as
	 * point multiplication done by the reference implementation given in 'multiply()'.
	 * This method tests multiplication of 'p' by every number of bitlength 'numBits' or less.
	 * @param numBits Try every multiplier up to this bitlength
	 */
	static void checkMultiplyAll( ECCurve curve, ECPoint p )
	{
		int numBits = curve.getOrder().bitLength();
		
		BigInteger bound = BigInteger.ONE.shiftLeft( numBits );
		BigInteger k = BigInteger.ZERO;

		do
		{
			ECPoint ref = p.referenceMultiply( k );
			MUST( ref.equals( p.multiply( k ) ) );
			k = k.add( BigInteger.ONE );
		}
		while( k.compareTo( bound ) < 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void checkSimpleECPoints( ECPoint[] points, ECCurve curve )
	{
		ECPoint infinity = curve.getInfinity();
		
		MUST( points[2].equals(  points[0].add( points[1] )  ) );
		MUST( points[2].equals(  points[1].add( points[0] )  ) );
		for( int i = 0; i < points.length; i++ )
		{
			MUST( points[i].equals(  points[i].add( infinity )  ) );
			MUST( points[i].equals(  infinity.add( points[i] )  ) );
		}

		MUST( points[3].equals(  points[0].twice()  ) );
		MUST( points[3].equals(  points[0].add( points[0] )  ) );

		ECPoint P = points[ 0 ];
		ECPoint _3P = P.add( P ).add( P );
		MUST( _3P.equals(  P.twicePlus(P)  ) );
		
		
		for( ECPoint p : points )
			CheckEC.checkAllPoints( p, infinity );

		for( ECPoint p : points )
		{
			// Add, Subsract
			MUST( p.twice().equals(  p.add( p )  ) );
			MUST( p.equals(  p.twice().subtract( p )  ) );
			MUST( p.equals(  p.twicePlus( p.negate() )  ) );
			MUST( infinity.equals(  p.subtract( p )  ) );
			MUST( p.equals(  p.add( infinity )  ) );
			MUST( p.equals(  infinity.add( p )  ) );
			MUST( infinity.equals(  infinity.add( infinity )  ) );
			MUST( infinity.equals(  infinity.twice()  ) );

			CheckEC.checkMultiplyAll( curve, p );
			CheckEC.checkMultiplyAll( curve, infinity );
		}
	}

}

