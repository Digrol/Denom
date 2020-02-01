// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.testcrypt;

import java.util.Random;
import org.denom.*;
import org.denom.crypt.*;
import org.denom.log.LogConsole;

import static org.denom.Ex.MUST;
import static org.denom.Binary.Bin;

// -----------------------------------------------------------------------------------------------------------------
public class TestDES3
{
	private static LogConsole log = new LogConsole();

	private final static int ITERATIONS = 100;
	private final static int DATA_SIZE = 50000;

	static Random rand = new Random( System.nanoTime() );

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		Binary key = new Binary( 16 );
		Binary data = Binary.Bin( "AB CD EF 00 AB CD EF 00" );
		Binary iv = new Binary( 8 );

		checkDES3( data, key, CryptoMode.ECB, iv );
		checkDES3( data, key, CryptoMode.CBC, iv );
		checkDES3( data, key, CryptoMode.CFB, iv );
		checkDES3( data, key, CryptoMode.OFB, iv );

		key = Bin().random( 16 );
		data = Bin().random( DATA_SIZE );
		iv = new Binary( 8 );

		measure( data, key, CryptoMode.CBC, iv );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void checkDES3( final Binary data, final Binary key, CryptoMode mode, final Binary iv )
	{
		for( int i = 0; i < 100; i++ )
		{
			key.random( 16 );
			data.random( rand.nextInt( 1024 ) + 1 );
			iv.random( 8 );

			DES3 new_des = new DES3( key );
			DES3Jce old_des = new DES3Jce( key );

			Binary new_encrypted = new_des.encrypt( data, mode, AlignMode.BLOCK, iv );
			Binary old_encrypted = old_des.encrypt( data, mode, AlignMode.BLOCK, iv );

			Binary new_decrypted = new_des.decrypt( new_encrypted, mode, AlignMode.BLOCK, iv );
			Binary old_decrypted = old_des.decrypt( old_encrypted, mode, AlignMode.BLOCK, iv );

			MUST( old_encrypted.equals( new_encrypted ) );
			MUST( old_decrypted.equals( new_decrypted ) );
			MUST( data.equals( new_decrypted ) );

			Binary new_ccs = new_des.calcCCS( data, AlignMode.BLOCK, CCSMode.CLASSIC );
			Binary old_ccs = old_des.calcCCS( data, AlignMode.BLOCK, CCSMode.CLASSIC );

			MUST( old_ccs.equals( new_ccs ) );

			old_ccs = old_des.calcCCS( data, AlignMode.BLOCK, CCSMode.FAST );
			new_ccs = new_des.calcCCS( data, AlignMode.BLOCK, CCSMode.FAST );
			MUST( old_ccs.equals( new_ccs ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void measure( final Binary data, final Binary key, CryptoMode mode, final Binary iv )
	{
		DES3 des3 = new DES3( key );
		long t = Ticker.measureMs( ITERATIONS, () ->
		{
			Binary crypt = des3.encrypt( data, mode, AlignMode.BLOCK, iv );
			des3.decrypt( crypt, mode, AlignMode.BLOCK, iv );
		} );
		log.writeln( "Time DES3 SLS: " + t + " ms" );


		DES3Jce des3Jce = new DES3Jce( key );
		t = Ticker.measureMs( ITERATIONS, () ->
		{
			Binary crypt = des3Jce.encrypt( data, mode, AlignMode.BLOCK, iv );
			des3Jce.decrypt( crypt, mode, AlignMode.BLOCK, iv );
		} );
		log.writeln( "Time DES3 JCE: " + t + " ms" );
	}

}