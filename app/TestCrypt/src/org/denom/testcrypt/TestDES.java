// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.testcrypt;


import java.util.Random;
import org.denom.*;
import org.denom.log.*;
import org.denom.crypt.*;

import static org.denom.Ex.MUST;
import static org.denom.Binary.Bin;

public class TestDES
{
	static LogConsole log = new LogConsole();

	static int ITERATIONS = 200;
	static int DATA_SIZE = 50000;
	static Random rand = new Random( System.nanoTime() );

	// -----------------------------------------------------------------------------------------------------------------
	static void check( String keyHex, String IV, String dataHex, String cryptHex, CryptoMode mode, AlignMode alignMode )
	{
		DES des = new DES( Bin(keyHex) );
		Binary crypt = des.encrypt( Bin( dataHex ), mode, alignMode, Bin(IV) );
		MUST( crypt.equals( cryptHex ) );

		Binary data = des.decrypt( crypt, mode, alignMode, Bin(IV) );
		MUST( data.equals( dataHex ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		String keyHex = "0123456789abcdef";
		String dataHex = "4e6f77206973207468652074696d6520666f7220616c6c20";

		check( keyHex, "0000000000000000", dataHex, "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53", CryptoMode.ECB, AlignMode.NONE );
		check( keyHex, "1234567890abcdef", dataHex, "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6", CryptoMode.CBC, AlignMode.NONE );
		check( keyHex, "1234567890abcdef", dataHex, "f3096249c7f46e51a69e839b1a92f78403467133898ea622", CryptoMode.CFB, AlignMode.NONE );

		checkEquals( CryptoMode.ECB );
		checkEquals( CryptoMode.CBC );
		checkEquals( CryptoMode.CFB );
		checkEquals( CryptoMode.OFB );

		Binary data = Bin().random( DATA_SIZE );
		measure( data, CryptoMode.CBC );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void checkEquals( CryptoMode mode )
	{
		DES des = new DES();
		DESJce desStd = new DESJce();

		Binary key = new Binary();
		Binary data = new Binary();
		Binary iv = new Binary();


		for( int i = 0; i < 100; i++ )
		{
			key.random( 8 );
			des.setKey( key );
			desStd.setKey( key );
			data.random( rand.nextInt( 1024 ) );
			iv.random( 8 );
			
			Binary crypt1 = des.encrypt( data, mode, AlignMode.BLOCK, iv );
			Binary crypt2 = desStd.encrypt( data, mode, AlignMode.BLOCK, iv );
			MUST( crypt2.equals( crypt1 ) );
			
			Binary data1 = des.decrypt( crypt1, mode, AlignMode.BLOCK, iv );
			Binary data2 = desStd.decrypt( crypt2, mode, AlignMode.BLOCK, iv );
			MUST( data2.equals( data1 ) );
			MUST( data1.equals( data ) );

			Binary new_ccs = des.calcCCS( data, AlignMode.BLOCK, CCSMode.CLASSIC );
			Binary old_ccs = desStd.calcCCS( data, AlignMode.BLOCK, CCSMode.CLASSIC );

			MUST( old_ccs.equals( new_ccs ) );

			old_ccs = desStd.calcCCS( data, AlignMode.BLOCK, CCSMode.FAST );
			new_ccs = des.calcCCS( data, AlignMode.BLOCK, CCSMode.FAST );
			MUST( old_ccs.equals( new_ccs ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void measure( final Binary data, CryptoMode mode )
	{
		DES des = new DES();
		des.generateKey();
		Binary iv = Bin().random( 8 );

		long t = Ticker.measureMs( ITERATIONS, () ->
		{
			Binary crypt = des.encrypt( data, mode, AlignMode.BLOCK, iv );
			des.decrypt( crypt, mode, AlignMode.BLOCK, iv );
		} );
		log.writeln( "Time DES    : " + t + " ms" );


		DESJce desJce = new DESJce( des.getKey() );
		t = Ticker.measureMs( ITERATIONS, () ->
		{
			Binary crypt = desJce.encrypt( data, mode, AlignMode.BLOCK, iv );
			desJce.decrypt( crypt, mode, AlignMode.BLOCK, iv );
		} );
		log.writeln( "Time DES JCE: " + t + " ms" );
	}

}
