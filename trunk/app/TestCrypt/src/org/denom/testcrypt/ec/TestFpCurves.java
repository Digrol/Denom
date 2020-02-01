package org.denom.testcrypt.ec;

import java.math.BigInteger;

import org.denom.*;
import org.denom.log.*;
import org.denom.crypt.ec.*;
import org.denom.crypt.ec.Fp.*;
import org.denom.crypt.ec.Fp.custom.*;
import org.denom.crypt.ec.ECCurve.ECPoint;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * Tests from X9.62.
 * Check and measure Fp curves custom vs. common implementation.
 */
public class TestFpCurves
{
	// -----------------------------------------------------------------------------------------------------------------
	// @param num - signs number
	public TestFpCurves( ILog log, int num )
	{
		log.writeln( getClass().getSimpleName() + " ... " );

		checkSimple();
		checkDecode();
		checkFixedSigns();
		checkECDH();
		checkECDHCUnified();
		checkECMQV();

		checkAllFpCurves();

		Ticker t = new Ticker();
		CheckEC.cross( log, "secp128r1", FpCurves.secp128r1(), new Secp128r1(), num );
		CheckEC.cross( log, "secp160r1", FpCurves.secp160r1(), new Secp160r1(), num );
		CheckEC.cross( log, "secp160r2", FpCurves.secp160r2(), new Secp160r2(), num );
		CheckEC.cross( log, "secp160k1", FpCurves.secp160k1(), new Secp160k1(), num );
		CheckEC.cross( log, "secp192k1", FpCurves.secp192k1(), new Secp192k1(), num );
		CheckEC.cross( log, "secp192r1", FpCurves.secp192r1(), new Secp192r1(), num );
		CheckEC.cross( log, "secp224r1", FpCurves.secp224r1(), new Secp224r1(), num );
		CheckEC.cross( log, "secp224k1", FpCurves.secp224k1(), new Secp224k1(), num );
		CheckEC.cross( log, "secp256r1", FpCurves.secp256r1(), new Secp256r1(), num );
		CheckEC.cross( log, "secp256k1", FpCurves.secp256k1(), new Secp256k1(), num );
		CheckEC.cross( log, "secp384r1", FpCurves.secp384r1(), new Secp384r1(), num );
		CheckEC.cross( log, "secp521r1", FpCurves.secp521r1(), new Secp521r1(), num );

		CheckEC.measureCurve( log, "curve25519", new Curve25519(), num );
		CheckEC.measureCurve( log, "gostR3410_2001_CryptoPro_A", FpCurves.gost3410_2001_A(), num );
		CheckEC.measureCurve( log, "tc26_gost3410_12_256_paramSetA", FpCurves.tc26_gost3410_12_256_A(), num );
		CheckEC.measureCurve( log, "tc26_gost3410_12_512_paramSetA", FpCurves.tc26_gost3410_12_512_A(), num );

		log.writeln( Colors.CYAN_I, "time: " + t.getDiffMs() );
		log.write( getClass().getSimpleName() + " - " );
		log.writeln( Colors.GREEN_I, "OK\n" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkAllFpCurves()
	{
		CheckEC.curveFpMath( FpCurves.secp112r1() );
		CheckEC.curveFpMath( FpCurves.secp112r2() );
		CheckEC.curveFpMath( FpCurves.secp128r1() );
		CheckEC.curveFpMath( FpCurves.secp128r2() );
		CheckEC.curveFpMath( FpCurves.secp160r1() );
		CheckEC.curveFpMath( FpCurves.secp160r2() );
		CheckEC.curveFpMath( FpCurves.secp160k1() );
		CheckEC.curveFpMath( FpCurves.secp192r1() );
		CheckEC.curveFpMath( FpCurves.secp192k1() );
		CheckEC.curveFpMath( FpCurves.secp224r1() );
		CheckEC.curveFpMath( FpCurves.secp224k1() );
		CheckEC.curveFpMath( FpCurves.secp256r1() );
		CheckEC.curveFpMath( FpCurves.secp256k1() );
		CheckEC.curveFpMath( FpCurves.secp384r1() );
		CheckEC.curveFpMath( FpCurves.secp521r1() );
		CheckEC.curveFpMath( FpCurves.prime192v2() );
		CheckEC.curveFpMath( FpCurves.prime192v3() );
		CheckEC.curveFpMath( FpCurves.prime239v1() );
		CheckEC.curveFpMath( FpCurves.prime239v2() );
		CheckEC.curveFpMath( FpCurves.prime239v3() );
		CheckEC.curveFpMath( FpCurves.gost3410_2001_A() );
		CheckEC.curveFpMath( FpCurves.gost3410_2001_B() );
		CheckEC.curveFpMath( FpCurves.gost3410_2001_C() );
		CheckEC.curveFpMath( FpCurves.tc26_gost3410_12_256_A() );
		CheckEC.curveFpMath( FpCurves.tc26_gost3410_12_512_A() );
		CheckEC.curveFpMath( FpCurves.tc26_gost3410_12_512_B() );
		CheckEC.curveFpMath( FpCurves.tc26_gost3410_12_512_C() );
		// Custom
		CheckEC.curveFpMath( new Curve25519() );
		CheckEC.curveFpMath( new Secp128r1() );
		CheckEC.curveFpMath( new Secp160k1() );
		CheckEC.curveFpMath( new Secp160r1() );
		CheckEC.curveFpMath( new Secp160r2() );
		CheckEC.curveFpMath( new Secp192k1() );
		CheckEC.curveFpMath( new Secp192r1() );
		CheckEC.curveFpMath( new Secp224k1() );
		CheckEC.curveFpMath( new Secp224r1() );
		CheckEC.curveFpMath( new Secp256k1() );
		CheckEC.curveFpMath( new Secp256r1() );
		CheckEC.curveFpMath( new Secp384r1() );
		CheckEC.curveFpMath( new Secp521r1() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkSimple()
	{
		ECCurve curve = new FpCurve(
			"",   // oid
			"1D", // q
			"04", // a
			"14", // b
			"26", // order
			"01", // cofactor
			"00"  // G
		);

		ECPoint[] points = {
			curve.createPoint( new BigInteger(  "5" ), new BigInteger( "22" ) ),
			curve.createPoint( new BigInteger( "16" ), new BigInteger( "27" ) ),
			curve.createPoint( new BigInteger( "13" ), new BigInteger(  "6" ) ),
			curve.createPoint( new BigInteger( "14" ), new BigInteger(  "6" ) )
		};

		CheckEC.checkSimpleECPoints( points, curve );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkDecode()
	{
		ECCurve curve = FpCurves.secp192r1();
		Binary encodedPoint = Bin("03 188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012" );
		ECPoint p = curve.decodePoint( encodedPoint ).normalize();

		MUST( p.getAffineXCoord().toBin().equals( "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012" ) );
		MUST( p.getAffineYCoord().toBin().equals( "07192b95ffc8da78631011ed6b24cdd573f977a11e794811" ) );

		MUST( encodedPoint.equals( p.getEncoded( true ) ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkFixedSigns()
	{
		CheckEC.fixedSign( FpCurves.secp192r1(),
			"1a8d598fc15bf0fd89030b5cb1111aeb92ae8baf5ea475fb", // d
			"02 62b12d60690cdcf330babab6e69763b471f994dd702d16a5", // Q
			"a9993e364706816aba3e25717850c26c9cd0d89d",
			"fa6de29746bbeb7f8bb1e761f85f7dfb2983169d82fa2f4e", // fixedK
			"885052380ff147b734c330c43d39b2c4a89f29b0f749fead e9ecc78106def82bf1070cf1d4d804c3cb390046951df686" ); // sign

		// X9.62, 1998, J.3.2, Page 155
		CheckEC.fixedSign( FpCurves.prime239v1(),
			"7ef7c6fabefffdea864206e80b0b08a9331ed93e698561b64ca0f7777f3d", // d
			"02 5b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70", // Q
			"a9993e364706816aba3e25717850c26c9cd0d89d",
			"656c7196bf87dcc5d1f1020906df2782360d36b2de7a17ece37d503784af", // fixedK
			"2cb7f36803ebb9c427c58d8265f11fc5084747133078fc279de874fbecb0 2eeae988104e9c2234a3c2beb1f53bfa5dc11ff36a875d1e3ccb1f7e45cf"); // sign

		// X9.62, 2005, L4.1
		CheckEC.fixedSign( FpCurves.secp224r1(),
			"39c01d092367bc5dc4e9def03510d0272c77daba7c152930aa8319ab", // d
			"03 fd44ec11f9d43d9d23b1e1d1c9ed6519b40ecf0c79f48cf476cc43f1", // Q
			"8797a3c693cc292441039a4e6bab7387f3b4f2a63d00ed384b378c79", // msg
			"92c5316c6d9e2a17b8615da13a689f7eddc81a7cd2a7d26058076cb9", // fixedK
			"fb6b02ad1857422dd0560d709d4fa60eab6e698cce964b2ab82c39ee a8060f8ae5fdd1326de60a55500edcea763f1e820da794a95b3c8f1a"); // sign

		CheckEC.fixedSign( FpCurves.secp224r1(),
			"39c01d092367bc5dc4e9def03510d0272c77daba7c152930aa8319ab", // d
			"03 fd44ec11f9d43d9d23b1e1d1c9ed6519b40ecf0c79f48cf476cc43f1", // Q
			"8797a3c693cc292441039a4e6bab7387f3b4f2a63d00ed384b378c79ff", // msg
			"92c5316c6d9e2a17b8615da13a689f7eddc81a7cd2a7d26058076cb9", // fixedK
			"fb6b02ad1857422dd0560d709d4fa60eab6e698cce964b2ab82c39ee a8060f8ae5fdd1326de60a55500edcea763f1e820da794a95b3c8f1a"); // sign

		CheckEC.fixedSign( FpCurves.secp224k1(),
			"be6f6e91fe96840a6518b56f3fe21689903a64fa729057ab872a9f51", // d
			"02 c5c9b38d3603fccd6994cbb9594e152b658721e483669bb42728520f", // Q
			"e5d5a7adf73c5476faee93a2c76ce94dc0557db04cdc189504779117920b896d", // msg
			"c39beac93db21c3266084429eb9b846b787c094f23a4de66447efbb3", // fixedK
			"8163e5941bed41da441b33e653c632a55a110893133351e20ce7cb75 d12c3fc289ddd5f6890dce26b65792c8c50e68bf551d617d47df15a8"); // sign

		// X9.62, 2005, L4.2
		CheckEC.fixedSign( FpCurves.secp256r1(),
			"2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8", // d
			"03 596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d", // Q
			"1bd4ed430b0f384b4e8d458eff1a8a553286d7ac21cb2f6806172ef5f94a06ad", // msg
			"a0640d4957f27d091ab1aebc69949d96e5ac2bb283ed5284a5674758b12f08df", // fixedK
			"d73cd3722bae6cc0b39065bb4003d8ece1ef2f7a8a55bfd677234b0b3b902650 d9c88297fefed8441e08dda69554a6452b8a0bd4a0ea1ddb750499f0c2298c2f"); // sign

		// X9.62, 2005, L4.3
		CheckEC.fixedSign( FpCurves.secp521r1(),
			"002e0f8d7f0d32af1d2b3b9886e23d4eaa4a3abe69ac1d510942ea9899782e9bdef68442052fdbbd2a7154b2008c5320e9006fdf923094662faaa4a3be6ea914547d", // d
			"02 0145e221ab9f71c5fe740d8d2b94939a09e2816e2167a7d058125a06a80c014f553e8d6764b048fb6f2b687cec72f39738f223d4ce6afcbff2e34774aa5d3c342cb3", // Q
			"6893b64bd3a9615c39c3e62ddd269c2baaf1d85915526083183ce14c2e883b48b193607c1ed871852c9df9c3147b574dc1526c55de1fe263a676346a20028a66", // msg
			"01fba787adad5156eadf770e1e2c1200600b995e59d157ca0684a9a01d84875626249613f73e36cc443bd66e9af17feb4e48521aa304de867c2e169ca2d3fc5c2f71", // fixedK
			"00661963dcfe341711f0bba30c81901a61d15ceab435bfd3822ebec19a9d53fcc31fc84c638326bae16491b2bdaf009205bbfd697c296a658c736a2b4dfe3b6ea636"
			  + "00792e03a4a4b622d2d3d3df8f3361c86be932be2c625e5a648c803d32bcd1e6f785750b655800bdc85eb8169d369dd1d465c3ebb4b81c9a041b14d954925166dd5e"); // sign
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkECDH()
	{
		ECDSA p1 = new ECDSA( FpCurves.prime239v1() ).generateKeyPair();
		ECDSA p2 = new ECDSA( FpCurves.prime239v1() ).generateKeyPair();
		Binary k1 = p1.calcDH( p2.getPublic() );
		Binary k2 = p2.calcDH( p1.getPublic() );
		MUST( k1.equals( k2 ) );

		k1 = p1.calcDHC( p2.getPublic() );
		k2 = p2.calcDHC( p1.getPublic() );
		MUST( k1.equals( k2 ) );

		p1 = new ECDSA( new Curve25519() ).generateKeyPair();
		p2 = new ECDSA( new Curve25519() ).generateKeyPair();
		k1 = p1.calcDH( p2.getPublic() );
		k2 = p2.calcDH( p1.getPublic() );
		MUST( k1.equals( k2 ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkECDHCUnified()
	{
		FpCurve curve = FpCurves.secp224r1();
		ECDSA static1 = new ECDSA( curve );
		static1.setPrivate( Bin("86d1735ca357890aeec8eccb4859275151356ecee9f1b2effb76b092") );
		static1.setPublic( Bin("02 0784e946ef1fae0cfe127042a310a018ba639d3f6b41f265904f0a7b") );
		ECDSA ephe1 = new ECDSA( curve );
		ephe1.setPrivate( Bin("764010b3137ef8d34a3552955ada572a4fa1bb1f5289f27c1bf18344") );
		ephe1.setPublic( Bin("02 b33713dc0d56215be26ee6c5e60ad36d12e02e78529ae3ff07873c6b" ) );

		ECDSA static2 = new ECDSA( curve );
		static2.setPrivate( Bin("e37964e391f5058fb43435352a9913438a1ec10831f755273285230a") );
		static2.setPublic( Bin("02 84c22d9575d09e280613c8758467f84869c6eede4f6c1b644517d6a7") );
		ECDSA ephe2 = new ECDSA( curve );
		ephe2.setPrivate( Bin("ab40d67f59ba7265d8ad33ade8f704d13a7ba2298b69172a7cd02515") );
		ephe2.setPublic( Bin("02 4b917e9ce693b277c8095e535ea81c2dea089446a8c55438eda750fb" ) );

		Binary x1 = static1.calcECDHCUnified( ephe1, static2.getPublic(), ephe2.getPublic() );
		Binary x2 = static2.calcECDHCUnified( ephe2, static1.getPublic(), ephe1.getPublic() );
		MUST( x1.equals( "80315a208b1cd6119264e5c03242b7db96379986fdc4c2f06bf88d0655cda75d4dc7e94a8df9f03239d5da9a18d364cebc6c63f01b6f4378" ) );
		MUST( x2.equals( x1 ), "Wrong ECDHC Unified" );

		// -------------------------------------------------------------------------------------------------------------
		curve = FpCurves.secp256r1();
		static1 = new ECDSA( curve );
		static1.setPrivate( Bin("2eb7ef76d4936123b6f13035045aedf45c1c7731f35d529d25941926b5bb38bb") );
		static1.setPublic( Bin("02 7581b35964a983414ebdd56f4ebb1ddcad10881b200666a51ae41306e1ecf1db") );
		ephe1 = new ECDSA( curve );
		ephe1.setPrivate( Bin("78acde388a022261767e6b3dd6dd016c53b70a084260ec87d395aec761c082de") );
		ephe1.setPublic( Bin("02 5b1e4cdeb0728333c0a51631b1a75269e4878d10732f4cb94d600483db4bd9ee" ) );

		static2 = new ECDSA( curve );
		static2.setPrivate( Bin("9c85898640a1b1de8ce7f557492dc1460530b9e17afaaf742eb953bb644e9c5a") );
		static2.setPublic( Bin("02 e4916d616803ff1bd9569f35b7d06f792f19c1fb4e6fa916d686c027a17d8dff") );
		ephe2 = new ECDSA( curve );
		ephe2.setPrivate( Bin("d6e11d5d3b85b201b8f4c12dadfad3000e267961a806a0658a2b859d44389599") );
		ephe2.setPublic( Bin("02 d1cd23c29d0fc865c316d44a1fd5adb6605ee47c9ddfec3a9b0a5e532d52704e") );

		x1 = static1.calcECDHCUnified( ephe1, static2.getPublic(), ephe2.getPublic() );
		x2 = static2.calcECDHCUnified( ephe2, static1.getPublic(), ephe1.getPublic() );
		MUST( x1.equals( "02886e53998b06d92f04e4579cbfa5f35c96334d3890298264e7f956da70966af07bf1b3abbaa8d76fbaf435508bdabbbbbdae1a191d91480ed88374c3552233" ) );
		MUST( x2.equals( x1 ), "Wrong ECDHC Unified" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkECMQV()
	{
		FpCurve curve = FpCurves.prime239v1();
		ECDSA static1 = new ECDSA( curve ).generateKeyPair();
		ECDSA ephe1 = new ECDSA( curve ).generateKeyPair();
		ECDSA static2 = new ECDSA( curve ).generateKeyPair();
		ECDSA ephe2 = new ECDSA( curve ).generateKeyPair();

		Binary x1 = static1.calcMQVAgreement( ephe1, static2.getPublic(), ephe2.getPublic() );
		Binary x2 = static2.calcMQVAgreement( ephe2, static1.getPublic(), ephe1.getPublic() );
		MUST( x2.equals( x1 ), "Wrong ECMQV agreement" );

		// -------------------------------------------------------------------------------------------------------------
		curve = FpCurves.secp160r1();

		static1 = new ECDSA( curve );
		static1.setPrivate( Bin("AA374FFC3CE144E6B073307972CB6D57B2A4E982") );
		static1.setPublic( Bin("02 51B4496FECC406ED0E75A24A3C03206251419DC0") );
		ephe1 = new ECDSA( curve );
		ephe1.setPrivate( Bin("149EC7EA3A220A887619B3F9E5B4CA51C7D1779C") );
		ephe1.setPublic( Bin("03 D99CE4D8BF52FA20BD21A962C6556B0F71F4CA1F" ) );

		static2 = new ECDSA( curve );
		static2.setPrivate( Bin("45FB58A92A17AD4B15101C66E74F277E2B460866") );
		static2.setPublic( Bin("03 49B41E0E9C0369C2328739D90F63D56707C6E5BC") );
		ephe2 = new ECDSA( curve );
		ephe2.setPrivate( Bin("18C13FCED9EADF884F7C595C8CB565DEFD0CB41E") );
		ephe2.setPublic( Bin("02 706E5D6E1F640C6E9C804E75DBC14521B1E5F3B5" ) );

		x1 = static1.calcMQVAgreement( ephe1, static2.getPublic(), ephe2.getPublic() );
		x2 = static2.calcMQVAgreement( ephe2, static1.getPublic(), ephe1.getPublic() );
		MUST( x1.equals( "5A6955CEFDB4E43255FB7FCF718611E4DF8E05AC" ) );
		MUST( x2.equals( x1 ), "Wrong ECMQV agreement" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestFpCurves( new LogConsole(), 100 );
	}
}