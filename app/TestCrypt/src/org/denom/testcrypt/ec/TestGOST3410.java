// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.testcrypt.ec;

import org.denom.*;
import org.denom.log.*;
import org.denom.crypt.hash.*;
import org.denom.crypt.ec.*;
import org.denom.crypt.ec.Fp.*;

import static org.denom.Binary.*;
import static org.denom.Ex.MUST;

/**
 *  ECGOST3410 tests are taken from GOST R 34.10-2001.
 */
public class TestGOST3410
{
	private static FpCurve gostR3410_2001_Test()
	{
		return new FpCurve( "",
			"8000000000000000000000000000000000000000000000000000000000000431", // p
			"07", // a
			"5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E", // b
			"8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3", // n
			"01", // h
			"02 0000000000000000000000000000000000000000000000000000000000000002" // G point
		);
	}

	private static FpCurve gostR3410_2012_Test()
	{
		return new FpCurve( "",
			"4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373", // p
			"07", // a
			"1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC", // b
			"4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF", // n
			"01", // h
			"02 24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A" // G point
		);
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TestGOST3410( ILog log )
	{
		log.write( getClass().getSimpleName() + "... " );

		IHash hashAlg = new GOST3411_94();
		checkSignVerify( hashAlg, gostR3410_2001_Test() );
		checkSignVerify( hashAlg, FpCurves.gost3410_2001_A() );
		checkSignVerify( hashAlg, FpCurves.gost3410_2001_B() );
		checkSignVerify( hashAlg, FpCurves.gost3410_2001_C() );

		hashAlg = new GOST3411_2012_256();
		checkSignVerify( hashAlg, FpCurves.tc26_gost3410_12_256_A() );
		hashAlg = new GOST3411_2012_512();
		checkSignVerify( hashAlg, gostR3410_2012_Test() );
		checkSignVerify( hashAlg, FpCurves.tc26_gost3410_12_512_A() );
		checkSignVerify( hashAlg, FpCurves.tc26_gost3410_12_512_B() );
		checkSignVerify( hashAlg, FpCurves.tc26_gost3410_12_512_C() );

		checkFixedSign();

		log.writeln( Colors.GREEN_I, "OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkFixedSign()
	{
		// GOST R 34.10-2012, Example A.1
		ECGOST ecgost = new ECGOST( gostR3410_2001_Test() );
		ecgost.setPrivate( Bin("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28") );
		ecgost.setPublic( Bin("02 7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B" ) );

		Binary hash = Bin("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5");
		ecgost.setFixedK( Bin("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3") );

		Binary sign = ecgost.sign( hash );
		Binary r = Bin("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493");
		Binary s = Bin("01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40");
		MUST( sign.equals( Bin( r, s ) ), "Wrong sign" );
		MUST( ecgost.verify( hash, sign ), "Wrong verify" );


		// GOST R 34.10-2012, Example A.2
		ecgost = new ECGOST( gostR3410_2012_Test() );
		ecgost.setPrivate( Bin("0BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4") );
		ecgost.setPublic( Bin("02 115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD5A515856D13314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1" ) );

		hash = Bin("3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C5917184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C");
		ecgost.setFixedK( Bin("0359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1") );

		sign = ecgost.sign( hash );
		r = Bin("2F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCACD35492558486B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36");
		s = Bin("1081B394696FFE8E6585E7A9362D26B6325F56778AADBC081C0BFBE933D52FF5823CE288E8C4F362526080DF7F70CE406A6EEB1F56919CB92A9853BDE73E5B4A");
		MUST( sign.equals( Bin( r, s ) ), "Wrong sign" );
		MUST( ecgost.verify( hash, sign ), "Wrong verify" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkSignVerify( IHash hashAlg, ECCurve curve )
	{
		Binary hash = hashAlg.calc( Bin().random( 200 ) );
		ECGOST ecgost3410 = new ECGOST( curve ).generateKeyPair();
		Binary sign = ecgost3410.sign( hash );
		MUST( ecgost3410.verify( hash, sign ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestGOST3410( new LogConsole() );
	}
}
