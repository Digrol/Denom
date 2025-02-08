// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package example;

import org.denom.Binary;
import org.denom.log.*;
import org.denom.format.*;
import org.denom.crypt.hash.*;
import org.denom.crypt.x509.CertificateX509v3;
import org.denom.crypt.RSA;
import org.denom.crypt.ec.ECAlg;
import org.denom.crypt.ec.Fp.custom.Secp256r1;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
public class UseASymCrypt
{
	static ILog log = new LogColoredConsoleWindow();
	static SHA256 hashAlg = new SHA256();

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		// Generate some random bytes
		Binary data = Bin().random( 200 );
		log.writeln( "Random data:" );
		log.writeln( Colors.GREEN, data.Hex(1, 8, 32, 4) );

		Binary dataHash = hashAlg.calc( data );
		useRSA( dataHash );
		useECDSA( dataHash );

		parseCertificateX509( "CERT_CI_ECDSA_NIST.der" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void useRSA( Binary dataHash )
	{
		// Sign with RSA
		RSA rsa = new RSA().generateKeyPair( 1024, Bin("03") );
		
		log.write( "\nSave RSA key in file... " );
		rsa.toJSON().save( "rsakey.json", 4 );
		log.writeln( "OK\n" );

		Binary sign = rsa.calcSignPSS( dataHash, hashAlg );
		log.writeln( "RSA signature:" );
		log.writeln( Colors.CYAN, sign.Hex(1, 8, 32, 4) );

		// Verify sign
		MUST( rsa.verifySignPSS( dataHash, hashAlg, sign ), "Wrong RSA signature" );
		log.writeln( Colors.GREEN_I, "RSA sign is OK." );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void useECDSA( Binary dataHash )
	{
		// Sign with EC
		ECAlg ecdsa = new ECAlg( new Secp256r1() ).generateKeyPair();
		Binary sign = ecdsa.signECDSAStd( dataHash );

		log.writeln( "\nECDSA signature (in ASN.1 format):" );
		log.writeln( Colors.CYAN, sign.Hex(1, 8, 32, 4) );

		log.writeln( "\nParse as TLV:" );
		log.writeln( Colors.CYAN_I, new BerTLVList( sign ).toString( 4 ) );

		// Verify sign
		MUST( ecdsa.verifyECDSAStd( dataHash, sign ), "Wrong ECDSA signature" );

		Binary signPlain = ecdsa.signECDSA( dataHash );
		log.writeln( "\nECDSA signature (plain - r || s):" );
		log.writeln( Colors.CYAN, signPlain.Hex(1, 8, 32, 4) );
		// Verify sign
		MUST( ecdsa.verifyECDSA( dataHash, signPlain ), "Wrong ECDSA signature" );

		log.writeln( Colors.GREEN_I, "ECDSA sign is OK." );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void parseCertificateX509( String fileName )
	{
		Binary certBin = new Binary().loadFromFile( fileName );
		CertificateX509v3 cert = new CertificateX509v3().fromBin( certBin );

		log.writeln( "\nSelf-signed X.509 Certificate in DER (TLV bytes):" );
		log.writeln( 0xFFEEBB33, cert.toString() );

		ECAlg ecdsa = new ECAlg( new Secp256r1() );
		ecdsa.setPublic( cert.subjectPublicKey );
		MUST( cert.verifySignature( ecdsa ), "Wrong signature" );
		log.writeln( Colors.GREEN_I, "Certificate sign is OK." );
	}

}
