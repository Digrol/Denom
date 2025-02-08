// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.testcrypt.ec;

import org.denom.*;
import org.denom.crypt.ec.ECAlg;
import org.denom.crypt.ec.Fp.custom.Secp256r1;
import org.denom.crypt.ec.Fp.custom.Secp521r1;
import org.denom.crypt.hash.*;
import org.denom.log.*;

import static org.denom.Binary.*;
import static org.denom.Ex.MUST;

/**
 * Test ECSDSA for EMV.
 * EMV Contactless Specifications for Payment Systems. Book E v1.0,  8.8.7  ECSDSA Signature.
 * The ECSDSA signature is an ECC version of the Schnorr digital signature scheme with 
 * appendix according to [ISO/IEC 14888-3]. This is the optimised version where only the 
 * x-coordinate is hashed rather than the (x, y) coordinates.
 */
public class TestECSDSA_X
{
	ILog log = new LogColoredConsoleWindow();

	SHA256 sha256 = new SHA256();
	SHA512 sha512 = new SHA512();

	// -----------------------------------------------------------------------------------------------------------------
	void Main()
	{
		testSecp256();
		BookE_Example256_Issuer();
		BookE_Example256_ICC();

		testSecp521();
		BookE_Example521_Issuer();
		BookE_Example521_ICC();

		log.writeln( Colors.GREEN_I, "All OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void testSecp256()
	{
		ECAlg alg = new ECAlg( new Secp256r1() );

		Binary msg = Bin().random( 300 );
		alg.generateKeyPair();

		Binary sign = alg.signECSDSA_X( msg, sha256 );
		MUST( alg.verifyECSDSA_X( msg, sha256, sign ), "Wrong verify 521 (sha 256)" );

		sign = alg.signECSDSA_X( msg, sha512 );
		MUST( alg.verifyECSDSA_X( msg, sha512, sign ), "Wrong verify 521 (sha 512)" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Book E Example, 3.2  Issuer ECC Public Key Certificate
	 */
	private void BookE_Example256_Issuer()
	{
		log.writeln( "Book E, Issuer Certificate 256" );

		Binary dCA = Bin("723222B51845E8B41A66263AE90E962148F9CCC3BE45B3E5902CEC0195F2AEAF" );
		Binary msg = Bin("120054133390FF1020301231123456A000000004E0CD7400578B1164FEA954658C763C5A94FB3514FA89DB5B3B447AE8F4D5DF870A" );
		Binary k = Bin("049916F4FD4046C1DBA9FBBD41C5A9643BDC6978C42371DDCD5D725E144B6446" );
		Binary sign = Bin("739061ADBC6FC71C8864EA9D3D6BAB5C9501C058D895FE0F69D92E22412953DC1ACCCBBE60809C5694C739CA54CC3FF4CF0964E1B946C3ED00C4E572A5021988" );

		ECAlg alg = new ECAlg( new Secp256r1() );
		alg.setPrivate( dCA );
		alg.setFixedK( k );
		Binary sign2 = alg.signECSDSA_X( msg, sha256 );
		log.writeln( "sign 256 CA:" );
		log.writeln( Colors.CYAN_I, sign.Hex( 0, 0, 32, 0 ));
		MUST( sign2.equals( sign ), "Wrong ecsdsa 256" );

		log.writeln( "OK\n" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Book E Example, 3.3  ICC ECC Public Key Certificate
	 */
	private void BookE_Example256_ICC()
	{
		log.writeln( "Book E, ICC Certificate 256" );

		Binary di   = Bin( "DD5015968F6E10BE471523C58716FC0A36A40B309E62039DF6ED9FC62C6EA5F8" );
		Binary msg  = Bin( "140000202912312359987654321000010260D3FB0E45A5E64834880571152BE93E241D216D407F6F000C263B1CC87517AF43CA1837F6B4321CA70262902037EFCE790DC583828AEA628FFAAEFC08618658" );
		Binary k    = Bin( "93C1BB40E845B014C0CE00325A2E89642B891EBF0265F16A1531671467909371" );
		Binary sign = Bin( "035824B9DD96765B97A0CC52C1B668B075ED86BE31DA1159C6F9128863B75A80BD863084A1C965C681AE72DF3B58A9CA8AEC8463DEF0A7FA35C0EE83A5269F65" );

		ECAlg alg = new ECAlg( new Secp256r1() );
		alg.setPrivate( di );
		alg.setFixedK( k );
		Binary sign2 = alg.signECSDSA_X( msg, sha256 );
		log.writeln( "sign 256 Issuer:" );
		log.writeln( Colors.CYAN_I, sign.Hex( 0, 0, 32, 0 ));
		MUST( sign2.equals( sign ), "Wrong ecsdsa 256" );

		log.writeln( "OK\n" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void testSecp521()
	{
		ECAlg alg = new ECAlg( new Secp521r1() );
		Binary msg = Bin().random( 200 );
		alg.generateKeyPair();

		Binary sign = alg.signECSDSA_X( msg, sha512 );
		MUST( alg.verifyECSDSA_X( msg, sha512, sign ), "Wrong verify 521 (sha 512)" );

		sign = alg.signECSDSA_X( msg, sha256 );
		MUST( alg.verifyECSDSA_X( msg, sha256, sign ), "Wrong verify 521 (sha 256)" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Book E Example, 4.2  Issuer ECC Public Key Certificate
	 */
	private void BookE_Example521_Issuer()
	{
		log.writeln( "Book E, Issuer Certificate 521" );

		Binary dCA  = Bin("018B05B1953B24AC49B340C24D6DD42CCFFDD795F6879C4B28475375CEEA2440D6180E7733BA7423B9CF9A61AAA6A3480B882BA6F9497F09613451877120383FF2BC" );
		Binary msg  = Bin("120054133390FF1120301231123456A000000004E1009C0AE6DC43AC03AA8285C9C67962B0B426587EB50DB41F7A5DD37BBB7E95831C8742384A1C880A561CE775946D473E4CD12FC03E4345ED93A515C6FAF722FA13E7" );
		Binary k    = Bin("01CEC53C7A0FC68F914CB3B06AAF89B04622B465AB8CB52DA2FAE7B2BF3E7754B1866900AEE2AFF453C8199617EC6E23E111CC813F622EEBECC51B4516CC37569D09");
		Binary sign = Bin("DCB625B0FC3F87241D38565B4CAE9B1B9D00A70B71EAF6F54ACDE94EEFE49C514724FAF5F7A4A25606F0CE7C89DC6EE4403D841EF7155B87363E8CE39EB7FEAC0158D88C6B23D71E7C5B8D4E9009BAADD96A0ECDA0C1305774F7CD65FE0A907711258DF9F13A9D70AE0DE200103F6FF9D80067E672A683F8E49602F8E94C6615B2EB");

		ECAlg alg = new ECAlg( new Secp521r1() );
		alg.setPrivate( dCA );
		alg.setFixedK( k );
		Binary sign2 = alg.signECSDSA_X( msg, sha512 );
		log.writeln( "sign 521 CA:" );
		log.writeln( Colors.CYAN_I, sign.Hex( 0, 0, 32, 0 ));
		MUST( sign2.equals( sign ), "Wrong ecsdsa 521" );

		MUST( alg.verifyECSDSA_X( msg, sha512, sign ), "Wrong verify 521" );
		log.writeln( "OK\n" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Book E Example, 4.3  ICC ECC Public Key Certificate
	 */
	private void BookE_Example521_ICC()
	{
		log.writeln( "Book E, ICC Certificate 521" );

		Binary di   = Bin( "00D069CF714C812DE247A3546AEA2A8098D707031FCB2EB93629255305FA6C6FFB8944E7FCF8C0D5C1115F5801797E49D61A562BCA08ACB61B1F756A3A3D9AF33635" );
		Binary msg  = Bin( "140000202912312359987654321000010260D3FB0E45A5E64834880571152BE93E241D216D407F6F000C263B1CC87517AF43CA1837F6B4321CA70262902037EFCE790DC583828AEA628FFAAEFC08618658" );
		Binary k    = Bin( "01EC03A29BF1F9CBA1EB306F4A3D63AB4C9B8955AEE4CBDFCA5A248B5CBC8DA0C4951E5565CC8BD025E0CF4D227B51B66DC628DB7D51723F82409D738599C9C96D43" );
		Binary sign = Bin( "AEE9050995E9DA36D574942FC1F0F6C1ABC085904CB124B668788681E4BC84B6FCB7F7DA9A01561C7F7F2318A1E03A52E76F729755D2F9279EEE1185DE31401C003857A1143939AC53F1BD478A71317541A87865FC76C09D8F8E0C00ECE27AE0F467301325D807B3B2F604AB2562EFA1CF1E614B554FFF07969A227ADD22539AA80D" );

		ECAlg alg = new ECAlg( new Secp521r1() );
		alg.setPrivate( di );
		alg.setFixedK( k );
		Binary sign2 = alg.signECSDSA_X( msg, sha512 );
		log.writeln( "sign 521 Issuer:" );
		log.writeln( Colors.CYAN_I, sign.Hex( 0, 0, 32, 0 ));
		MUST( sign2.equals( sign ), "Wrong ecsdsa 521" );

		MUST( alg.verifyECSDSA_X( msg, sha512, sign ), "Wrong verify 521" );
		log.writeln( "OK\n" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestECSDSA_X().Main();
	}
}
