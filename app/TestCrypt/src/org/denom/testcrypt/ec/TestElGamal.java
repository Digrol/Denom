package org.denom.testcrypt.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.denom.log.*;
import org.denom.crypt.ec.*;
import org.denom.crypt.ec.Fp.FpCurves;
import org.denom.crypt.ec.ECCurve.ECPoint;

import static org.denom.Ex.MUST;

public class TestElGamal
{
	// -----------------------------------------------------------------------------------------------------------------
	public TestElGamal( ILog log )
	{
		log.write( getClass().getSimpleName() + "... " );

		ECCurve curve = FpCurves.secp192r1();
		ECDSA ecdsa = new ECDSA( curve ).generateKeyPair();

		BigInteger N = curve.getOrder();
		BigInteger val = BigInteger.valueOf( 20 );
		ECPoint data = curve.GMul( val );
		MUST( data.equals( ecdsa.decrypt( ecdsa.encrypt( data ) ) ), "Failed to decrypt" );
		
		val = new BigInteger( N.bitLength() - 1, new SecureRandom() );
		data = curve.GMul( val );
		MUST( data.equals( ecdsa.decrypt( ecdsa.encrypt( data ) ) ), "Failed to decrypt" );

		doTest( ecdsa, BigInteger.valueOf( 20 ) );

		BigInteger rand = new BigInteger( N.bitLength() - 1, new SecureRandom() );
		doTest( ecdsa, rand );
		doSameKeyTest( ecdsa, rand );

		log.writeln( Colors.GREEN_I, "OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void doTest( ECDSA ecdsa, BigInteger value )
	{
		ECPoint data = ecdsa.getCurve().GMul( value );
		ECPoint[] pair = ecdsa.encrypt( data );

		ECDSA ec2 = ecdsa.clone().generateKeyPair();
		ECPoint[] srcPair = pair;

		// re-encrypt the message portion
		pair = ec2.transform( srcPair );
		ECPoint p = ecdsa.decrypt( new ECPoint[]{ srcPair[0], pair[1] } );

		// decrypt the fully transformed point.
		ECPoint result = ec2.decrypt( new ECPoint[]{ pair[0], p } );
		MUST( data.equals( result ), "point pair failed to decrypt back to original" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void doSameKeyTest( ECDSA ecdsa, BigInteger value )
	{
		ECPoint data = ecdsa.getCurve().GMul( value );
		ECPoint[] pair = ecdsa.encrypt( data );

		ECPoint[] srcPair = pair;
		// re-encrypt the message portion
		pair = ecdsa.transformRandom( srcPair );

		ECPoint result = ecdsa.decrypt( pair );
		MUST( data.equals( result ), "point pair failed to decrypt back to original" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestElGamal( new LogConsole() );
	}

}
