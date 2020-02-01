// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

import org.denom.Binary;
import org.denom.log.*;
import org.denom.format.*;
import org.denom.crypt.hash.*;
import org.denom.crypt.RSA;
import org.denom.crypt.ec.ECDSA;
import org.denom.crypt.ec.Fp.custom.Secp256r1;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
public class UseASymCrypt
{
	public static void main( String[] args )
	{
		ILog log = new LogColoredConsoleWindow();

		// Generate some random bytes
		Binary data = Bin().random( 200 );
		log.writeln( "Random data:" );
		log.writeln( Colors.GREEN, data.Hex(1, 8, 32, 4) );

		SHA256 hashAlg = new SHA256();
		Binary hash = hashAlg.calc( data );

		// Sign with RSA
		RSA rsa = new RSA().generateKeyPair( 1024, Bin("03") );
		
		log.write( "\nSave RSA key in file... " );
		rsa.toJSON().save( "rsakey.json", 4 );
		log.writeln( "OK\n" );

		Binary sign = rsa.calcSignPSS( hash, hashAlg );
		log.writeln( "RSA signature:" );
		log.writeln( Colors.CYAN, sign.Hex(1, 8, 32, 4) );

		// Verify sign
		MUST( rsa.verifySignPSS( hash, hashAlg, sign ), "Wrong RSA signature" );
		log.writeln( Colors.GREEN_I, "RSA sign is OK." );


		// Sign with EC
		ECDSA ecdsa = new ECDSA( new Secp256r1() ).generateKeyPair();
		sign = ecdsa.signStd( hash );

		log.writeln( "\nECDSA signature (in ASN.1 format):" );
		log.writeln( Colors.CYAN, sign.Hex(1, 8, 32, 4) );

		log.writeln( "\nParse as TLV:" );
		log.writeln( Colors.CYAN_I, new BerTLVList( sign ).toString( 4 ) );

		// Verify sign
		MUST( ecdsa.verifyStd( hash, sign ), "Wrong ECDSA signature" );

		log.writeln( Colors.GREEN_I, "ECDSA sign is OK." );
	}

}
