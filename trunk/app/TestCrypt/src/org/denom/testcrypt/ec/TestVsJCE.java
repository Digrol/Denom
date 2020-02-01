package org.denom.testcrypt.ec;

import org.denom.*;
import org.denom.log.*;
import org.denom.crypt.hash.SHA256;
import org.denom.crypt.ec.*;
import org.denom.crypt.ec.Fp.custom.*;

import static org.denom.Ex.*;
import static org.denom.Binary.Bin;


// -----------------------------------------------------------------------------------------------------------------
/**
 * Test custom implementation VS. java.security implementation.
 */
public class TestVsJCE
{
	private final int signsNumber;

	// -----------------------------------------------------------------------------------------------------------------
	public TestVsJCE( ILog log, int signsNumber )
	{
		this.signsNumber = signsNumber;
		ECDSAStd std = new ECDSAStd();
		ECDSA custom = new ECDSA( new Secp256r1() );

		crossCheck( log, std, custom );
		measure( log, std, custom );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void crossCheck( ILog log, ECDSAStd std, ECDSA custom )
	{
		log.write( "Cross check 'Secp256r1' vs. JCE ... " );

		for(int i = 0; i < 50; ++i )
		{
			custom.generateKeyPair();
			std.setPublicKeyX509( custom.getPublicX509() );
			std.setPrivateKeyPKCS8( custom.getPrivatePKCS8() );

			Binary data = Bin().random( 32 );
			Binary hash = new SHA256().calc( data );
			MUST( std.verify( data, custom.signStd( hash ) ) );
			MUST( custom.verifyStd( hash, std.sign( data ) ) );

			std.generateKeyPair();
			custom.setPublicX509( std.getPublicKeyX509() );
			custom.setPrivatePKCS8( std.getPrivateKeyPKCS8() );
			MUST( std.verify( data, custom.signStd( hash ) ) );
			MUST( custom.verifyStd( hash, std.sign( data ) ) );
		}
		log.writeln( Colors.GREEN_I, "OK" );
	}


	// -----------------------------------------------------------------------------------------------------------------
	private String pad( String text, int len )
	{
		return Strings.PadLeft( text, len, ' ' );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void measure( ILog log, ECDSAStd std, ECDSA custom )
	{
		Binary hash = Bin().random( 32 );

		log.writeln( "Measure 'Secp256r1' vs. JCE (" + signsNumber + "):" );
		log.writeln( 0xFFFF80FF, "        generate    sign  verify" );


		log.write( Colors.KEY, pad( "JCE", 8 ) );
		long t = Ticker.measureMs( signsNumber, () -> std.generateKeyPair() );
		log.write( Colors.CYAN_I, pad("" + t, 8) );

		t = Ticker.measureMs( signsNumber, () -> std.sign( hash ) );
		log.write( Colors.CYAN_I, pad("" + t, 8) );
		
		Binary sign2 = std.sign( hash ); 
		t = Ticker.measureMs( signsNumber, () -> std.verify( hash, sign2 ) );
		log.writeln( Colors.CYAN_I, pad("" + t, 8) );


		log.write( Colors.KEY, pad( "Custom", 8 ) );
		t = Ticker.measureMs( signsNumber, () -> custom.generateKeyPair() );
		log.write( Colors.CYAN_I, pad("" + t, 8) );
		
		t = Ticker.measureMs( signsNumber, () -> custom.sign( hash ) );
		log.write( Colors.CYAN_I, pad("" + t, 8) );

		Binary sign = custom.sign( hash ); 
		t = Ticker.measureMs( signsNumber, () -> custom.verify( hash, sign ) );
		log.writeln( Colors.CYAN_I, pad("" + t, 8) );

		log.writeln( Colors.DARK_GRAY, "--------------------------------" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestVsJCE( new LogConsole(), 200 );
	}
}
