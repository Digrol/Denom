package org.denom.testcrypt.ec.rfc7748;

import java.util.Arrays;
import java.security.SecureRandom;
import org.denom.log.*;
import org.denom.crypt.ec.rfc7748.X25519;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
public class TestX25519
{
	private final SecureRandom RANDOM = new SecureRandom();

	public TestX25519( ILog log )
	{
		log.write( getClass().getSimpleName() + "... " );

		X25519.precompute();

		testConsistency();
		testECDH();
		checkECDHVector();
		checkIterated( 1000 );

		byte[] r = new byte[ 32 ];
		X25519.scalarMult(
			Bin( "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4" ).getBytes(), 0,
			Bin( "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c" ).getBytes(), 0,
			r, 0 );
		MUST( Bin( r ).equals( "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" ) );

		X25519.scalarMult(
			Bin( "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d" ).getBytes(), 0,
			Bin( "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493" ).getBytes(), 0,
			r, 0 );
		MUST( Bin( r ).equals( "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957" ) );

		log.writeln( Colors.GREEN_I, "OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void testConsistency()
	{
		byte[] u = new byte[ 32 ];
		u[ 0 ] = 9;
		byte[] k = new byte[ 32 ];
		byte[] rF = new byte[ 32 ];
		byte[] rV = new byte[ 32 ];

		for( int i = 1; i <= 100; ++i )
		{
			RANDOM.nextBytes( k );
			X25519.scalarMultBase( k, 0, rF, 0 );
			X25519.scalarMult( k, 0, u, 0, rV, 0 );
			MUST( Arrays.equals( rF, rV ), "Consistency #" + i );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void testECDH()
	{
		byte[] kA = new byte[ 32 ];
		byte[] kB = new byte[ 32 ];
		byte[] qA = new byte[ 32 ];
		byte[] qB = new byte[ 32 ];
		byte[] sA = new byte[ 32 ];
		byte[] sB = new byte[ 32 ];

		for( int i = 1; i <= 100; ++i )
		{
			// Each party generates an ephemeral private key, ...
			RANDOM.nextBytes( kA );
			RANDOM.nextBytes( kB );

			// publishes their private key
			X25519.scalarMultBase( kA, 0, qA, 0 );
			X25519.scalarMultBase( kB, 0, qB, 0 );

			// computes the shared secret
			X25519.scalarMult( kA, 0, qB, 0, sA, 0 );
			X25519.scalarMult( kB, 0, qA, 0, sB, 0 );

			// which is the same for both parties.
			MUST( Arrays.equals( sA, sB ), "ECDH #" + i );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkECDHVector()
	{
		byte[] a = Bin( "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a" ).getBytes();
		byte[] b = Bin( "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb" ).getBytes();

		byte[] aPub = new byte[ 32 ];
		X25519.scalarMultBase( a, 0, aPub, 0 );
		MUST( Bin( aPub ).equals( "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" ) );

		byte[] bPub = new byte[ 32 ];
		X25519.scalarMultBase( b, 0, bPub, 0 );
		MUST( Bin( bPub ).equals( "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f" ) );

		byte[] res = new byte[ 32 ];
		X25519.scalarMult( a, 0, bPub, 0, res, 0 );
		MUST( Bin( res ).equals( "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" ) );
		X25519.scalarMult( b, 0, aPub, 0, res, 0 );
		MUST( Bin( res ).equals( "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkIterated( int count )
	{
		byte[] k = new byte[ 32 ];
		k[ 0 ] = 9;
		byte[] u = new byte[ 32 ];
		u[ 0 ] = 9;
		byte[] r = new byte[ 32 ];

		int iterations = 0;
		while( iterations < count )
		{
			X25519.scalarMult( k, 0, u, 0, r, 0 );

			System.arraycopy( k, 0, u, 0, 32 );
			System.arraycopy( r, 0, k, 0, 32 );

			++iterations;
			
			if( iterations == 1 )
				MUST( Bin( k ).equals( "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079" ) );

			if( iterations == 1000 )
				MUST( Bin( k ).equals( "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51" ) );
				
			if( iterations == 1000000 )
				MUST( Bin( k ).equals( "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424" ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestX25519( new LogConsole() );
	}
}
