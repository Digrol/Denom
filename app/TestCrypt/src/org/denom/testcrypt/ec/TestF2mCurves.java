package org.denom.testcrypt.ec;

import java.math.BigInteger;

import org.denom.*;
import org.denom.log.*;
import org.denom.crypt.ec.*;
import org.denom.crypt.ec.F2m.*;
import org.denom.crypt.ec.F2m.custom.*;
import org.denom.crypt.ec.ECCurve.ECPoint;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * Tests from X9.62.
 * Check and measure F2m curves custom vs. common implementation.
 */
public class TestF2mCurves
{
	private final ILog log;
	
	// -----------------------------------------------------------------------------------------------------------------
	// @param num - signs number
	public TestF2mCurves( ILog log, int num )
	{
		this.log = log;
		log.writeln( getClass().getSimpleName() + " ... " );

		checkSimple();
		checkFixedSigns();
		checkECMQV();
		checkAllF2mCurves();
		crossChecks( num );

		log.write( getClass().getSimpleName() + " - " );
		log.writeln( Colors.GREEN_I, "OK\n" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void crossChecks( int num )
	{
		Ticker t = new Ticker();
		CheckEC.cross( log, "sect113r1", F2mCurves.sect113r1(), Sect113.r1(), num );
		CheckEC.cross( log, "sect113r2", F2mCurves.sect113r2(), Sect113.r2(), num );

		CheckEC.cross( log, "sect131r1", F2mCurves.sect131r1(), Sect131.r1(), num );
		CheckEC.cross( log, "sect131r2", F2mCurves.sect131r2(), Sect131.r2(), num );

		CheckEC.cross( log, "sect163k1", F2mCurves.sect163k1(), Sect163.k1(), num );
		CheckEC.cross( log, "sect163r1", F2mCurves.sect163r1(), Sect163.r1(), num );
		CheckEC.cross( log, "sect163r2", F2mCurves.sect163r2(), Sect163.r2(), num );

		CheckEC.cross( log, "sect193r1", F2mCurves.sect193r1(), Sect193.r1(), num );
		CheckEC.cross( log, "sect193r2", F2mCurves.sect193r2(), Sect193.r2(), num );

		CheckEC.cross( log, "sect233k1", F2mCurves.sect233k1(), Sect233.k1(), num );
		CheckEC.cross( log, "sect233r1", F2mCurves.sect233r1(), Sect233.r1(), num );
		CheckEC.cross( log, "sect239k1", F2mCurves.sect239k1(), Sect239.k1(), num );

		CheckEC.cross( log, "sect283k1", F2mCurves.sect283k1(), Sect283.k1(), num );
		CheckEC.cross( log, "sect283r1", F2mCurves.sect283r1(), Sect283.r1(), num );
		log.writeln( Colors.CYAN_I, "time: " + t.getDiffMs() );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	private void checkAllF2mCurves()
	{
		CheckEC.curveF2mMath( F2mCurves.sect113r1() );
		CheckEC.curveF2mMath( F2mCurves.sect113r2() );
		CheckEC.curveF2mMath( F2mCurves.sect131r1() );
		CheckEC.curveF2mMath( F2mCurves.sect131r2() );
		CheckEC.curveF2mMath( F2mCurves.sect163k1() );
		CheckEC.curveF2mMath( F2mCurves.sect163r1() );
		CheckEC.curveF2mMath( F2mCurves.sect163r2() );
		CheckEC.curveF2mMath( F2mCurves.sect193r1() );
		CheckEC.curveF2mMath( F2mCurves.sect193r2() );
		CheckEC.curveF2mMath( F2mCurves.sect233k1() );
		CheckEC.curveF2mMath( F2mCurves.sect233r1() );
		CheckEC.curveF2mMath( F2mCurves.sect239k1() );
		CheckEC.curveF2mMath( F2mCurves.sect283k1() );
		CheckEC.curveF2mMath( F2mCurves.sect283r1() );
		CheckEC.curveF2mMath( F2mCurves.sect409k1() );
		CheckEC.curveF2mMath( F2mCurves.sect409r1() );
		CheckEC.curveF2mMath( F2mCurves.sect571k1() );
		CheckEC.curveF2mMath( F2mCurves.sect571r1() );
		CheckEC.curveF2mMath( F2mCurves.c2pnb163v1() );
		CheckEC.curveF2mMath( F2mCurves.c2pnb163v2() );
		CheckEC.curveF2mMath( F2mCurves.c2pnb163v3() );
		CheckEC.curveF2mMath( F2mCurves.c2pnb176w1() );
		CheckEC.curveF2mMath( F2mCurves.c2tnb191v1() );
		CheckEC.curveF2mMath( F2mCurves.c2tnb191v2() );
		CheckEC.curveF2mMath( F2mCurves.c2tnb191v3() );
		CheckEC.curveF2mMath( F2mCurves.c2pnb208w1() );
		CheckEC.curveF2mMath( F2mCurves.c2tnb239v1() );
		CheckEC.curveF2mMath( F2mCurves.c2tnb239v2() );
		CheckEC.curveF2mMath( F2mCurves.c2tnb239v3() );
		CheckEC.curveF2mMath( F2mCurves.c2pnb272w1() );
		CheckEC.curveF2mMath( F2mCurves.c2pnb304w1() );
		CheckEC.curveF2mMath( F2mCurves.c2tnb359v1() );
		CheckEC.curveF2mMath( F2mCurves.c2pnb368w1() );
		CheckEC.curveF2mMath( F2mCurves.c2tnb431r1() );
		// Custom
		CheckEC.curveF2mMath( Sect113.r1() );
		CheckEC.curveF2mMath( Sect113.r2() );
		CheckEC.curveF2mMath( Sect131.r1() );
		CheckEC.curveF2mMath( Sect131.r2() );
		CheckEC.curveF2mMath( Sect163.k1() );
		CheckEC.curveF2mMath( Sect163.r1() );
		CheckEC.curveF2mMath( Sect163.r2() );
		CheckEC.curveF2mMath( Sect193.r1() );
		CheckEC.curveF2mMath( Sect193.r2() );
		CheckEC.curveF2mMath( Sect233.k1() );
		CheckEC.curveF2mMath( Sect233.r1() );
		CheckEC.curveF2mMath( Sect239.k1() );
		CheckEC.curveF2mMath( Sect283.k1() );
		CheckEC.curveF2mMath( Sect283.r1() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkSimple()
	{
		// Irreducible polynomial for TPB z^4 + z + 1
		ECCurve curve = new F2mCurve( "", 4, 1, 0, 0,
			"08", // a = z^3
			"09", // b = z^3 + 1
			"17", // n
			"01",  // h
			"00"
		);

		ECPoint[] points = {
			curve.createPoint( new BigInteger( "0010", 2 ), new BigInteger( "1111", 2 ) ),
			curve.createPoint( new BigInteger( "1100", 2 ), new BigInteger( "1100", 2 ) ),
			curve.createPoint( new BigInteger( "0001", 2 ), new BigInteger( "0001", 2 ) ),
			curve.createPoint( new BigInteger( "1011", 2 ), new BigInteger( "0010", 2 ) ),
		};
		
		CheckEC.checkSimpleECPoints( points, curve );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkFixedSigns()
	{
		String data = "a9993e364706816aba3e25717850c26c9cd0d89d";

		// X9.62, 1998, J.2.1, Page 100
		CheckEC.fixedSign( F2mCurves.c2tnb191v1(),
			"340562e1dda332f9d2aec168249b5696ee39d0ed4d03760f", // d
			"03 5de37e756bd55d72e3768cb396ffeb962614dea4ce28a2e7", // Q
			data,
			"3eeace72b4919d991738d521879f787cb590aff8189d2b69", // fixedK
			"038e5a11fb55e4c65471dcd4998452b1e02d8af7099bb930 0c9a08c34468c244b4e5d6b21b3c68362807416020328b6e" ); // sign

		// X9.62, 1998, J.2.1, Page 100
		CheckEC.fixedSign( F2mCurves.c2tnb239v1(),
			"151a30a6d843db3b25063c5108255cc4448ec0f4d426d4ec884502229c96", // d
			"03 5894609ccecf9a92533f630de713a958e96c97ccb8f5abb5a688a238deed", // Q
			data,
			"18d114bdf47e2913463e50375dc92784a14934a124f83d28caf97c5d8aab", // fixedK
			"03210d71ef6c10157c0d1053dff93e8b085f1e9bc22401f7a24798a63c00 1c8c4343a8ecbf7c4d4e48f7d76d5658bc027c77086ec8b10097deb307d6" ); // sign

		// large hash
		CheckEC.fixedSign( F2mCurves.c2tnb239v1(),
			"151a30a6d843db3b25063c5108255cc4448ec0f4d426d4ec884502229c96", // d
			"03 5894609ccecf9a92533f630de713a958e96c97ccb8f5abb5a688a238deed", // Q
			"4f668c49cf73006769747861b6d156bbd3b746f2b978b385a99728bc95751acac4e307c591396f3b2c39ebbf0f298ab07926814d5b2dc26c9cd0d89d",
			"18d114bdf47e2913463e50375dc92784a14934a124f83d28caf97c5d8aab", // fixedK
			"03210d71ef6c10157c0d1053dff93e8b085f1e9bc22401f7a24798a63c00 150022a69285e9daef797f31901fe19aeb49a35963cfccae65da5972c125" ); // sign
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkECMQV()
	{
		ECCurve curve = F2mCurves.sect163k1();
		ECDSA static1 = new ECDSA( curve );
		static1.setPrivate( Bin("03A41434AA99C2EF40C8495B2ED9739CB2155A1E0D") );
		static1.setPublic( Bin("03037D529FA37E42195F10111127FFB2BB38644806BC") );
		ECDSA ephe1 = new ECDSA( curve );
		ephe1.setPrivate( Bin("032FC4C61A8211E6A7C4B8B0C03CF35F7CF20DBD52") );
		ephe1.setPublic( Bin("02015198E74BC2F1E5C9A62B80248DF0D62B9ADF8429" ) );

		ECDSA static2 = new ECDSA( curve );
		static2.setPrivate( Bin("0057E8A78E842BF4ACD5C315AA0569DB1703541D96") );
		static2.setPublic( Bin("03072783FAAB9549002B4F13140B88132D1C75B3886C") );
		ECDSA ephe2 = new ECDSA( curve );
		ephe2.setPrivate( Bin("02BD198B83A667A8D908EA1E6F90FD5C6D695DE94F") );
		ephe2.setPublic( Bin("03067E3AEA3510D69E8EDD19CB2A703DDC6CF5E56E32") );

		Binary x1 = static1.calcMQVAgreement( ephe1, static2.getPublic(), ephe2.getPublic() );
		Binary x2 = static2.calcMQVAgreement( ephe2, static1.getPublic(), ephe1.getPublic() );
		MUST( x1.equals( "038359FFD30C0D5FC1E6154F483B73D43E5CF2B503" ) );
		MUST( x2.equals( x1 ), "Wrong ECDHC Unified" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestF2mCurves( new LogConsole(), 100 );
	}
}