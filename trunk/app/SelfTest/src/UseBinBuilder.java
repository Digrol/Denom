
import org.denom.log.*;
import org.denom.Binary;
import org.denom.crypt.RSA;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
public class UseBinBuilder
{
	static ILog log = new LogColoredConsoleWindow();
	
	public static void main( String[] args )
	{
		RSA rsa2 = new RSA().generateKeyPair( 512, Bin("010001") );
		RSA rsa = new RSA();

		Binary b;

		b = rsa.toBin();
		log.writeln( "RSA key: \n" + b.Hex( 4, 16, 32, 0 ) );
		rsa.fromBin( b );

		rsa.setPublic( rsa2.getN(), rsa2.getE() );

		b = rsa.toBin();
		log.writeln( "RSA key: \n" + b.Hex( 4, 16, 32, 0 ) );
		RSA rsa3 = new RSA().fromBin( b );


		rsa.setPrivate( rsa2.getN(), rsa2.getD() );

		Binary sign = rsa.calcSignPKCS1v1_5( Bin(20, 0x67) );
		MUST( rsa3.verifySignPKCS1v1_5( Bin(20, 0x67), sign ) );

		log.writeln( Colors.GREEN_I, "OK" );
	}
}