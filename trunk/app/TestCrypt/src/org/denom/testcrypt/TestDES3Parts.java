// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.testcrypt;

import java.util.Random;
import org.denom.*;
import org.denom.log.*;
import org.denom.crypt.*;

import static org.denom.Ex.MUST;
import static org.denom.Binary.Bin;

public class TestDES3Parts
{
	static int BLOCK_SIZE = DES3.BLOCK_SIZE;
	static Random rand = new Random( System.nanoTime() );

	public static final int ITERATIONS = 1000;
	public static final int DATA_SIZE = 1000;

	private static ILog log = new LogConsole();

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		Binary key = Bin( BLOCK_SIZE * 2 );
		Binary data = Bin( BLOCK_SIZE );
		Binary iv = Bin( BLOCK_SIZE );

		checkNonStream( data, key, CryptoMode.ECB, AlignMode.BLOCK, iv );
		checkNonStream( data, key, CryptoMode.CBC, AlignMode.BLOCK, iv );
		checkNonStream( data, key, CryptoMode.CFB, AlignMode.BLOCK, iv );
		checkNonStream( data, key, CryptoMode.OFB, AlignMode.BLOCK, iv );

		checkNonStream( data, key, CryptoMode.ECB, AlignMode.NONE, iv );
		checkNonStream( data, key, CryptoMode.CBC, AlignMode.NONE, iv );
		checkNonStream( data, key, CryptoMode.CFB, AlignMode.NONE, iv );
		checkNonStream( data, key, CryptoMode.OFB, AlignMode.NONE, iv );

		checkCCSFirstNextLast( data, key, CCSMode.FAST, AlignMode.BLOCK, iv );
		checkCCSFirstNextLast( data, key, CCSMode.FAST, AlignMode.NONE, iv );
		checkCCSFirstNextLast( data, key, CCSMode.CLASSIC, AlignMode.NONE, iv );
		checkCCSFirstNextLast( data, key, CCSMode.CLASSIC, AlignMode.BLOCK, iv );

		checkFirstNextLast( data, key, CryptoMode.ECB, AlignMode.BLOCK, iv );
		checkFirstNextLast( data, key, CryptoMode.CBC, AlignMode.BLOCK, iv );
		checkFirstNextLast( data, key, CryptoMode.CFB, AlignMode.BLOCK, iv );
		checkFirstNextLast( data, key, CryptoMode.OFB, AlignMode.BLOCK, iv );

		checkFirstNextLast( data, key, CryptoMode.ECB, AlignMode.NONE, iv );
		checkFirstNextLast( data, key, CryptoMode.CBC, AlignMode.NONE, iv );
		checkFirstNextLast( data, key, CryptoMode.CFB, AlignMode.NONE, iv );
		checkFirstNextLast( data, key, CryptoMode.OFB, AlignMode.NONE, iv );

		data.random( DATA_SIZE );
		key.random( BLOCK_SIZE * 2 );
		iv.random( BLOCK_SIZE );

		measure( log, data, key, CryptoMode.CBC, iv );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void measure( ILog log, final Binary data, final Binary key, CryptoMode mode, final Binary iv )
	{
		DES3 des = new DES3( key );
		long t = Ticker.measureMs( ITERATIONS, () ->
		{
			Binary crypt = des.encrypt( data, mode, AlignMode.BLOCK, iv );
			des.decrypt( crypt, mode, AlignMode.BLOCK, iv );
		} );
		System.out.println( "Time SLS: " + t + " ms" );


		DES3Jce desJce = new DES3Jce( key );
		t = Ticker.measureMs( ITERATIONS, () ->
		{
			Binary crypt = desJce.encrypt( data, mode, AlignMode.BLOCK, iv );
			desJce.decrypt( crypt, mode, AlignMode.BLOCK, iv );
		} );
		System.out.println( "Time JCE: " + t + " ms" );

	}

	// -----------------------------------------------------------------------------------------------------------------
	static void checkFirstNextLast( final Binary data, final Binary key, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		for( int i = 0; i < 100; ++i )
		{
			iv.random( BLOCK_SIZE );
			key.random( 2 * BLOCK_SIZE );

			DES3Jce desJce = new DES3Jce( key );
			DES3 des = new DES3( key );

			// данные должны быть выровнены - потому кратно размеру блока
			if( alignMode == AlignMode.NONE )
			{
				data.random( 101 * BLOCK_SIZE );
			}
			// данные любого размера - в последнем блоке будет выравнивание
			else
			{
				data.random( 101 * BLOCK_SIZE + rand.nextInt( 1024 ) );
			}

			//--------------------------------------------------------------------
			// ШИФРОВАНИЕ
			//--------------------------------------------------------------------
			Binary data1 = data.slice( 0, i * BLOCK_SIZE );
			Binary data2 = data.slice( (i    ) * BLOCK_SIZE, BLOCK_SIZE );
			Binary data3 = data.slice( (i + 1) * BLOCK_SIZE, BLOCK_SIZE );
			Binary data4 = data.slice( (i + 2) * BLOCK_SIZE, data.size() - (i + 2) * BLOCK_SIZE );

			Binary crypt1 = Bin( data1.size() );
			Binary crypt2 = Bin( data2.size() );
			Binary crypt3 = Bin( data3.size() );
			Binary crypt4 = Bin( data4.size() );

			des.encryptFirst( data1, crypt1, cryptMode, alignMode, iv );
			des.encryptNext( data2, crypt2 );
			des.encryptNext( data3, crypt3 );
			des.encryptLast( data4, crypt4 );

			Binary crypt = crypt1.add( crypt2 ).add( crypt3 ).add( crypt4 );
			Binary cryptJce = desJce.encrypt( data, cryptMode, alignMode, iv );

			MUST( cryptJce.equals( crypt ) );

			//--------------------------------------------------------------------
			// ДЕШИФРОВАНИЕ
			//--------------------------------------------------------------------
			crypt1 = crypt.slice( 0, i * BLOCK_SIZE );
			crypt2 = crypt.slice( (i    ) * BLOCK_SIZE, BLOCK_SIZE );
			crypt3 = crypt.slice( (i + 1) * BLOCK_SIZE, BLOCK_SIZE );
			crypt4 = crypt.slice( (i + 2) * BLOCK_SIZE, crypt.size() - (i + 2) * BLOCK_SIZE );

			Binary dataSls1 = Bin( crypt1.size() );
			Binary dataSls2 = Bin( crypt2.size() );
			Binary dataSls3 = Bin( crypt3.size() );
			Binary dataSls4 = Bin( crypt4.size() );

			des.decryptFirst( crypt1, dataSls1, cryptMode, alignMode, iv );
			des.decryptNext( crypt2, dataSls2 );
			des.decryptNext( crypt3, dataSls3 );
			des.decryptLast( crypt4, dataSls4 );

			Binary dataSls = dataSls1.add( dataSls2 ).add( dataSls3 ).add( dataSls4 );

			// дефолтный DES
			Binary dataJce = desJce.decrypt( cryptJce, cryptMode, alignMode, iv );

			MUST( dataJce.equals( dataSls ) );
			MUST( data.equals( dataJce ) );
			MUST( data.equals( dataSls ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void checkCCSFirstNextLast( Binary data, final Binary key, CCSMode ccsMode, AlignMode alignMode, final Binary iv )
	{
		for ( int i = 0; i < 99; ++i )
		{
			iv.random( BLOCK_SIZE );
			key.random( 2 * BLOCK_SIZE );

			DES3Jce des_default = new DES3Jce( key );
			DES3 des_stream = new DES3( key );

			// данные должны быть выровнены - потому кратно размеру блока
			if( alignMode == AlignMode.NONE )
			{
				data.random( 101 * BLOCK_SIZE );
			}
			// данные любого размера - в последнем блоке будет выравнивание
			else
			{
				data.random( 101 * BLOCK_SIZE + rand.nextInt( 1024 ) );
			}

			//--------------------------------------------------------------------
			// ВЫЧИСЛЕНИЕ КРИПТОГРАФИЧЕСКОЙ КОНТРОЛЬНОЙ СУММЫ
			//--------------------------------------------------------------------
			// потоковый DES - разбиваем данные различными способами на куски
			Binary data1 = data.slice( 0, i * BLOCK_SIZE );
			Binary data2 = data.slice( (i    ) * BLOCK_SIZE, BLOCK_SIZE );
			Binary data3 = data.slice( (i + 1) * BLOCK_SIZE, BLOCK_SIZE );
			Binary data4 = data.slice( (i + 2) * BLOCK_SIZE, data.size() - (i + 2) * BLOCK_SIZE );

			Binary ccs_new = Bin();

			des_stream.calcCCSfirst( data1, alignMode, ccsMode, iv );
			des_stream.calcCCSnext( data2 );
			des_stream.calcCCSnext( data3 );
			des_stream.calcCCSlast( data4, ccs_new );

			// дефолтный DES
			Binary ccs_old = des_default.calcCCS( data, alignMode, ccsMode, iv );

			MUST( ccs_old.equals( ccs_new ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void checkNonStream( final Binary data, final Binary key, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		for ( int i = 0; i < 100; ++i )
		{
			iv.random( BLOCK_SIZE );
			key.random( 2 * BLOCK_SIZE );

			DES3Jce des_default = new DES3Jce( key );
			DES3 des_stream = new DES3( key );

			key.random( 2 * BLOCK_SIZE );
			des_default.setKey( key );
			des_stream.setKey( key );

			// данные должны быть выровнены - потому кратно размеру блока
			if( alignMode == AlignMode.NONE )
			{
				data.random( BLOCK_SIZE );
			}
			// данные любого размера - в последнем блоке будет выравнивание
			else
			{
				data.random( BLOCK_SIZE + rand.nextInt( 1024 ) );
			}

			//--------------------------------------------------------------------
			// ШИФРОВАНИЕ - ДЕШИФРОВАНИЕ
			Binary crypt_new = des_stream.encrypt( data, cryptMode, alignMode, iv );
			Binary crypt_old = des_default.encrypt( data, cryptMode, alignMode, iv );

			MUST( crypt_old.equals( crypt_new ) );

			Binary decrypt_new = des_stream.decrypt( crypt_old, cryptMode, alignMode, iv );
			Binary decrypt_old = des_default.decrypt( crypt_old, cryptMode, alignMode, iv );

			MUST( decrypt_old.equals( decrypt_new ) );

			MUST( data.equals( decrypt_old ) );
			MUST( data.equals( decrypt_new ) );
			//--------------------------------------------------------------------

			//--------------------------------------------------------------------
			// ВЫЧИСЛЕНИЕ КОНТРОЛЬНОЙ СУММЫ
			Binary ccs_old;
			Binary ccs_new;

			ccs_old = des_default.calcCCS( data, alignMode, CCSMode.CLASSIC, iv );
			ccs_new = des_stream.calcCCS( data, alignMode, CCSMode.CLASSIC, iv );

			MUST( ccs_old.equals( ccs_new ) );

			ccs_old = des_default.calcCCS( data, alignMode, CCSMode.FAST, iv );
			ccs_new = des_stream.calcCCS( data, alignMode, CCSMode.FAST, iv );

			MUST( ccs_old.equals( ccs_new ) );
		}
	}

}