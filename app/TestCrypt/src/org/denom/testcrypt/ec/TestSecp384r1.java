package org.denom.testcrypt.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.denom.log.*;
import org.denom.crypt.ec.*;
import org.denom.crypt.ec.Fp.FpCurveAbstract;
import org.denom.crypt.ec.Fp.custom.Secp384r1;
import org.denom.crypt.ec.ECCurve.*;

import static org.denom.Ex.MUST;

public class TestSecp384r1
{
	private final SecureRandom RANDOM = new SecureRandom();

	private final FpCurveAbstract curve = new Secp384r1();
	private final BigInteger P = curve.getP();

	public TestSecp384r1( ILog log )
	{
		log.write( getClass().getSimpleName() + "... " );
		testMultiply1();
		testMultiply2();
		testSquare();
		testSquare_CarryBug();
		testSquare_CarryBug_Reported();
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

	private void testSquare_CarryBug()
	{
		int COUNT = 100;

		for( int i = 0; i < COUNT; ++i )
		{
			ECElement x = generateSquareInput_CarryBug();

			BigInteger X = x.toBigInteger();
			BigInteger R = X.multiply( X ).mod( P );

			ECElement z = x.square();
			BigInteger Z = z.toBigInteger();

			MUST( R.equals( Z ) );
		}
	}

	/*
	 * Based on another example input demonstrating the carry propagation bug in Nat192.square, as
	 * reported by Joseph Friel on dev-crypto.
	 */
	private void testSquare_CarryBug_Reported()
	{
		ECElement x = fe( new BigInteger( "2fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd", 16 ) );

		BigInteger X = x.toBigInteger();
		BigInteger R = X.multiply( X ).mod( P );

		ECElement z = x.square();
		BigInteger Z = z.toBigInteger();

		MUST( R.equals( Z ) );
	}

	private ECElement fe( BigInteger x )
	{
		return curve.fromBigInteger( x );
	}

	private ECElement generateMultiplyInput_Random()
	{
		return fe( new BigInteger( curve.getFieldSize() + 32, RANDOM ).mod( P ) );
	}

	private ECElement generateSquareInput_CarryBug()
	{
		int[] x = new int[ 12 ];
		x[ 0 ] = RANDOM.nextInt() >>> 1;
		x[ 6 ] = 2;
		x[ 10 ] = -1 << 16;
		x[ 11 ] = -1;

		return fe( Nat.toBigInteger( 12, x ) );
	}
}
