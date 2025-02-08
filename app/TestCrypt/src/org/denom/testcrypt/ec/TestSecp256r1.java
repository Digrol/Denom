// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.testcrypt.ec;

import java.math.BigInteger;
import org.denom.log.*;
import java.security.SecureRandom;

import org.denom.crypt.ec.*;
import org.denom.crypt.ec.Fp.FpCurveAbstract;
import org.denom.crypt.ec.Fp.custom.*;
import org.denom.crypt.ec.ECCurve.*;

import static org.denom.Ex.*;


public class TestSecp256r1
{
	private final SecureRandom RANDOM = new SecureRandom();

	private final FpCurveAbstract curve = new Secp256r1();
	private final BigInteger P = curve.getP();

	public TestSecp256r1( ILog log )
	{
		log.write( getClass().getSimpleName() + "... " );

		testMultiply1();
		testMultiply2();
		testSquare();
		testMultiply_OpenSSLBug();
		testSquare_OpenSSLBug();

		log.writeln( Colors.GREEN_I, "OK" );
	}

	private void testMultiply1()
	{
		int COUNT = 1000;

		for( int i = 0; i < COUNT; ++i )
		{
			ECElement x = generateMultiplyInput_Random();
			ECElement y = generateMultiplyInput_Random();

			BigInteger X = x.toBigInteger(), Y = y.toBigInteger();
			BigInteger R = X.multiply( Y ).mod( P );

			ECElement z = x.multiply( y );
			BigInteger Z = z.toBigInteger();

			MUST( R.equals( Z ) );
		}
	}


	private void testMultiply2()
	{
		int COUNT = 100;
		ECElement[] inputs = new ECElement[ COUNT ];
		BigInteger[] INPUTS = new BigInteger[ COUNT ];

		for( int i = 0; i < inputs.length; ++i )
		{
			inputs[ i ] = generateMultiplyInput_Random();
			INPUTS[ i ] = inputs[ i ].toBigInteger();
		}

		for( int j = 0; j < inputs.length; ++j )
		{
			for( int k = 0; k < inputs.length; ++k )
			{
				BigInteger R = INPUTS[ j ].multiply( INPUTS[ k ] ).mod( P );

				ECElement z = inputs[ j ].multiply( inputs[ k ] );
				BigInteger Z = z.toBigInteger();

				MUST( R.equals( Z ) );
			}
		}
	}


	private void testSquare()
	{
		int COUNT = 1000;

		for( int i = 0; i < COUNT; ++i )
		{
			ECElement x = generateMultiplyInput_Random();

			BigInteger X = x.toBigInteger();
			BigInteger R = X.multiply( X ).mod( P );

			ECElement z = x.square();
			BigInteger Z = z.toBigInteger();

			MUST( R.equals( Z ) );
		}
	}

	/**
	 * Test multiplication with specifically selected values that triggered a bug in the modular
	 * reduction in OpenSSL (last affected version 0.9.8g).
	 *
	 * See "Practical realisation and elimination of an ECC-related software bug attack", B. B.
	 * Brumley, M. Barbarosa, D. Page, F. Vercauteren.
	 */
	private void testMultiply_OpenSSLBug()
	{
		int COUNT = 100;

		for( int i = 0; i < COUNT; ++i )
		{
			ECElement x = generateMultiplyInputA_OpenSSLBug();
			ECElement y = generateMultiplyInputB_OpenSSLBug();

			BigInteger X = x.toBigInteger(), Y = y.toBigInteger();
			BigInteger R = X.multiply( Y ).mod( P );

			ECElement z = x.multiply( y );
			BigInteger Z = z.toBigInteger();

			MUST( R.equals( Z ) );
		}
	}

	/**
	 * Test squaring with specifically selected values that triggered a bug in the modular reduction
	 * in OpenSSL (last affected version 0.9.8g).
	 *
	 * See "Practical realisation and elimination of an ECC-related software bug attack", B. B.
	 * Brumley, M. Barbarosa, D. Page, F. Vercauteren.
	 */
	private void testSquare_OpenSSLBug()
	{
		int COUNT = 100;

		for( int i = 0; i < COUNT; ++i )
		{
			ECElement x = generateSquareInput_OpenSSLBug();

			BigInteger X = x.toBigInteger();
			BigInteger R = X.multiply( X ).mod( P );

			ECElement z = x.square();
			BigInteger Z = z.toBigInteger();

			MUST( R.equals( Z ) );
		}
	}

	private ECElement fe( BigInteger x )
	{
		return curve.fromBigInteger( x );
	}

	private ECElement generateMultiplyInput_Random()
	{
		return fe( new BigInteger( curve.getFieldSize() + 32, RANDOM ).mod( P ) );
	}

	private ECElement generateMultiplyInputA_OpenSSLBug()
	{
		int[] x = new int[8];
		x[ 0 ] = RANDOM.nextInt() >>> 1;
		x[ 4 ] = 3;
		x[ 7 ] = -1;

		return fe( Nat.toBigInteger( 8, x ) );
	}

	private ECElement generateMultiplyInputB_OpenSSLBug()
	{
		int[] x = new int[8];
		x[ 0 ] = RANDOM.nextInt() >>> 1;
		x[ 3 ] = 1;
		x[ 7 ] = -1;

		return fe( Nat.toBigInteger( 8, x ) );
	}

	private ECElement generateSquareInput_OpenSSLBug()
	{
		int[] x = new int[8];
		x[ 0 ] = RANDOM.nextInt() >>> 1;
		x[ 4 ] = 2;
		x[ 7 ] = -1;

		return fe( Nat.toBigInteger( 8, x ) );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestSecp256r1( new LogConsole() );
	}

}
