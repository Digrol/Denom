package org.denom.testcrypt.ec.rfc7748;

import java.util.Arrays;
import java.security.SecureRandom;
import org.denom.log.*;
import org.denom.crypt.ec.rfc7748.X448;

import static org.denom.Ex.MUST;
import static org.denom.Binary.Bin;

public class TestX448
{
	private final SecureRandom RANDOM = new SecureRandom();

	// -----------------------------------------------------------------------------------------------------------------
	public TestX448( ILog log )
	{
		log.write( getClass().getSimpleName() + "... " );

		X448.precompute();

		testConsistency();
		testECDH();
		checkECDHVector();
		checkIterated( 1000 );

		byte[] r = new byte[ 56 ];
		byte[] k = Bin("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3").getBytes();
		byte[] u = Bin("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086").getBytes();
		X448.scalarMult( k, 0, u, 0, r, 0 );
		MUST( Bin(r).equals( "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f" ) );

		k = Bin("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f").getBytes();
		u = Bin("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db").getBytes();
		X448.scalarMult( k, 0, u, 0, r, 0 );
		MUST( Bin(r).equals( "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d" ) );

		log.writeln( Colors.GREEN_I, "OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void testConsistency()
	{
		byte[] u = new byte[ 56 ];
		u[ 0 ] = 5;
		byte[] k = new byte[ 56 ];
		byte[] rF = new byte[ 56 ];
		byte[] rV = new byte[ 56 ];

		for( int i = 1; i <= 100; ++i )
		{
			RANDOM.nextBytes( k );
			X448.scalarMultBase( k, 0, rF, 0 );
			X448.scalarMult( k, 0, u, 0, rV, 0 );
			MUST( Arrays.equals( rF, rV ), "Consistency #" + i );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void testECDH()
	{
		byte[] kA = new byte[ 56 ];
		byte[] kB = new byte[ 56 ];
		byte[] qA = new byte[ 56 ];
		byte[] qB = new byte[ 56 ];
		byte[] sA = new byte[ 56 ];
		byte[] sB = new byte[ 56 ];

		for( int i = 1; i <= 100; ++i )
		{
			// Each party generates an ephemeral private key, ...
			RANDOM.nextBytes( kA );
			RANDOM.nextBytes( kB );

			// ... publishes their public key, ...
			X448.scalarMultBase( kA, 0, qA, 0 );
			X448.scalarMultBase( kB, 0, qB, 0 );

			// ... computes the shared secret, ...
			X448.scalarMult( kA, 0, qB, 0, sA, 0 );
			X448.scalarMult( kB, 0, qA, 0, sB, 0 );

			// ... which is the same for both parties.
			MUST( Arrays.equals( sA, sB ), "ECDH #" + i );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkECDHVector()
	{
		byte[] a = Bin( "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b" ).getBytes();
		byte[] b = Bin( "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d" ).getBytes();

		byte[] aPub = new byte[ 56 ];
		X448.scalarMultBase( a, 0, aPub, 0 );
		MUST( Bin( aPub ).equals( "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0" ) );

		byte[] bPub = new byte[ 56 ];
		X448.scalarMultBase( b, 0, bPub, 0 );
		MUST( Bin( bPub ).equals( "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609" ) );

		String sK = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";
		byte[] res = new byte[ 56 ];
		X448.scalarMult( a, 0, bPub, 0, res, 0 );
		MUST( Bin( res ).equals( sK ) );
		X448.scalarMult( b, 0, aPub, 0, res, 0 );
		MUST( Bin( res ).equals( sK ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkIterated( int count )
	{
		byte[] k = new byte[ 56 ];
		k[ 0 ] = 5;
		byte[] u = new byte[ 56 ];
		u[ 0 ] = 5;
		byte[] r = new byte[ 56 ];

		int iterations = 0;
		while( iterations < count )
		{
			X448.scalarMult( k, 0, u, 0, r, 0 );

			System.arraycopy( k, 0, u, 0, 56 );
			System.arraycopy( r, 0, k, 0, 56 );

			++iterations;

			if( iterations == 1 )
				MUST( Bin(k).equals( "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113" ) );
			
			if( iterations == 1000 )
				MUST( Bin(k).equals( "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38" ) );
			
			if( iterations == 1000000 )
				MUST( Bin(k).equals( "077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37" ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestX448( new LogConsole() );
	}

}
