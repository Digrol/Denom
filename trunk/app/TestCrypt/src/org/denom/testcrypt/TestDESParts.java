// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.testcrypt;

import java.util.Random;
import org.denom.*;
import org.denom.crypt.*;

import static org.denom.Ex.MUST;
import static org.denom.Binary.Bin;

public class TestDESParts
{
	private static final int BLOCK_SIZE = DES.BLOCK_SIZE;
	static Random rand = new Random( System.nanoTime() );

	public static void checkSpeed( final Binary data, final Binary key, CryptoMode mode, final Binary iv )
	{
		long startTime;

		// DES
		startTime = System.nanoTime();
		DES des_new = new DES( key );
		for( int i = 0; i < ITERATIONS; i++ )
		{
			Binary new_encrypted = des_new.encrypt( data, mode, AlignMode.BLOCK, iv );
			des_new.decrypt( new_encrypted, mode, AlignMode.BLOCK, iv );
		}
		String str1 = "TIME_NEW: " + (System.nanoTime() - startTime) / 1000000 + " ms" ;

		// дефолтный DES
		startTime = System.nanoTime();
		DESJce des_old = new DESJce( key );
		for( int i = 0; i < ITERATIONS; i++ )
		{
			Binary old_encrypted = des_old.encrypt( data, mode, AlignMode.BLOCK, iv );
			des_old.decrypt( old_encrypted, mode, AlignMode.BLOCK, iv );
		}
		String str2 = "TIME_OLD: " + (System.nanoTime() - startTime) / 1000000 + " ms" ;

		System.out.println( str1 +" "+ str2 );
	}


	public static void checkFirstNextLast( final Binary data, final Binary key, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		for ( int i = 0; i < 100; ++i )
		{
			key.random( BLOCK_SIZE );
			iv.random( BLOCK_SIZE );

			DESJce des_default = new DESJce( key );
			DES des = new DES( key );

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
			// потоковый DES - разбиваем данные различными способами на куски
				Binary data1 = data.slice( 0, i * BLOCK_SIZE );
				Binary data2 = data.slice( (i    ) * BLOCK_SIZE, BLOCK_SIZE );
				Binary data3 = data.slice( (i + 1) * BLOCK_SIZE, BLOCK_SIZE );
				Binary data4 = data.slice( (i + 2) * BLOCK_SIZE, data.size() - (i + 2) * BLOCK_SIZE );

				Binary encrypt1 = Bin( data1.size() );
				Binary encrypt2 = Bin( data2.size() );
				Binary encrypt3 = Bin( data3.size() );
				Binary encrypt4 = Bin( data4.size() );

				des.encryptFirst( data1, encrypt1, cryptMode, alignMode, iv );
				des.encryptNext( data2, encrypt2 );
				des.encryptNext( data3, encrypt3 );
				des.encryptLast( data4, encrypt4 );

				Binary crypt_new = encrypt1.add( encrypt2 ).add( encrypt3 ).add( encrypt4 );
			// дефолтный DES
				Binary crypt_old = des_default.encrypt( data, cryptMode, alignMode, iv );

				MUST( crypt_old.equals( crypt_new ), "OLD_EN!=NEW_EN" );
			//--------------------------------------------------------------------
			// ДЕШИФРОВАНИЕ
			//--------------------------------------------------------------------
			// потоковый DES - разбиваем данные различными способами на куски
				Binary crypt1 = crypt_new.slice( 0, i * BLOCK_SIZE );
				Binary crypt2 = crypt_new.slice( (i    ) * BLOCK_SIZE, BLOCK_SIZE );
				Binary crypt3 = crypt_new.slice( (i + 1) * BLOCK_SIZE, BLOCK_SIZE );
				Binary crypt4 = crypt_new.slice( (i + 2) * BLOCK_SIZE, crypt_new.size() - (i + 2) * BLOCK_SIZE );

				Binary decrypt1 = Bin( crypt1.size() );
				Binary decrypt2 = Bin( crypt2.size() );
				Binary decrypt3 = Bin( crypt3.size() );
				Binary decrypt4 = Bin( crypt4.size() );

				des.decryptFirst( crypt1, decrypt1, cryptMode, alignMode, iv );
				des.decryptNext( crypt2, decrypt2 );
				des.decryptNext( crypt3, decrypt3 );
				des.decryptLast( crypt4, decrypt4 );

				Binary decrypt_new = decrypt1.add( decrypt2 ).add( decrypt3 ).add( decrypt4 );
			// дефолтный DES
				Binary decrypt_old = des_default.decrypt( crypt_old, cryptMode, alignMode, iv );

				MUST( decrypt_old.equals( decrypt_new ), "OLD_DE!=NEW_DE" );
			//-------------------------------------------------------------------

				MUST( data.equals( decrypt_old ), "data!=decrypt_old" );
				MUST( data.equals( decrypt_new ), "data!=decrypt_new");
		}
		System.out.println( "checkFirstNextLast: success" );
	}


	public static void checkCCSFirstNextLast( final Binary data, final Binary key, CCSMode ccsMode, AlignMode alignMode, final Binary iv )
	{
		for ( int i = 0; i < 99; ++i )
		{
			key.random( BLOCK_SIZE );
			iv.random( BLOCK_SIZE );

			DESJce des_default = new DESJce( key );
			DES des_stream = new DES( key );

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

				Binary ccs_new = Bin( BLOCK_SIZE );

				des_stream.calcCCSfirst( data1, alignMode, ccsMode, iv );
				des_stream.calcCCSnext( data2 );
				des_stream.calcCCSnext( data3 );
				des_stream.calcCCSlast( data4, ccs_new );

			// дефолтный DES
				Binary ccs_old = des_default.calcCCS( data, alignMode, ccsMode, iv );

				MUST( ccs_old.equals( ccs_new ), "OLD_CCS != NEW_CCS" );
		}
		System.out.println( "checkCCSFirstNextLast: success" );
	}

	public static void checkNonStream( final Binary data, final Binary key, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		for ( int i = 0; i < 100; ++i )
		{
			key.random( BLOCK_SIZE );
			iv.random( BLOCK_SIZE );

			DESJce des_default = new DESJce( key );
			DES des_stream = new DES( key );

			key.random( BLOCK_SIZE );
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

				MUST( crypt_old.equals( crypt_new ), "OLD_EN!=NEW_EN" );

				Binary decrypt_new = des_stream.decrypt( crypt_old, cryptMode, alignMode, iv );
				Binary decrypt_old = des_default.decrypt( crypt_old, cryptMode, alignMode, iv );

				MUST( decrypt_old.equals( decrypt_new ), "OLD_DE!=NEW_DE" );

				MUST( data.equals( decrypt_old ), "data!=decrypt_old" );
				MUST( data.equals( decrypt_new ), "data!=decrypt_new");
			//--------------------------------------------------------------------

			//--------------------------------------------------------------------
			// ВЫЧИСЛЕНИЕ КОНТРОЛЬНОЙ СУММЫ
				Binary ccs_old;
				Binary ccs_new;

				ccs_old = des_default.calcCCS( data, AlignMode.BLOCK, CCSMode.CLASSIC, iv );
				ccs_new = des_stream.calcCCS( data, AlignMode.BLOCK, CCSMode.CLASSIC, iv );

				MUST( ccs_old.equals( ccs_new ), "CCS_OLD!=CCS_NEW" );

				ccs_old = des_default.calcCCS( data, AlignMode.BLOCK, CCSMode.FAST, iv );
				ccs_new = des_stream.calcCCS( data, AlignMode.BLOCK, CCSMode.FAST, iv );

				MUST( ccs_old.equals( ccs_new ), "CCS_OLD!=CCS_NEW" );
		}
		System.out.println( "checkNonStream: success" );
	}

	public static final int ITERATIONS = 1000;
	public static final int DATA_SIZE = 1000;

	public static void main( String[] args )
	{
		Binary key = Bin( BLOCK_SIZE );
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

		checkCCSFirstNextLast( data, key, CCSMode.CLASSIC, AlignMode.NONE, iv );
		checkCCSFirstNextLast( data, key, CCSMode.CLASSIC, AlignMode.BLOCK, iv );
		checkCCSFirstNextLast( data, key, CCSMode.FAST, AlignMode.NONE, iv );
		checkCCSFirstNextLast( data, key, CCSMode.FAST, AlignMode.BLOCK, iv );

		checkFirstNextLast( data, key, CryptoMode.ECB, AlignMode.BLOCK, iv );
		checkFirstNextLast( data, key, CryptoMode.CBC, AlignMode.BLOCK, iv );
		checkFirstNextLast( data, key, CryptoMode.CFB, AlignMode.BLOCK, iv );
		checkFirstNextLast( data, key, CryptoMode.OFB, AlignMode.BLOCK, iv );

		checkFirstNextLast( data, key, CryptoMode.ECB, AlignMode.NONE, iv );
		checkFirstNextLast( data, key, CryptoMode.CBC, AlignMode.NONE, iv );
		checkFirstNextLast( data, key, CryptoMode.CFB, AlignMode.NONE, iv );
		checkFirstNextLast( data, key, CryptoMode.OFB, AlignMode.NONE, iv );

		data.random( DATA_SIZE );
		key.random( BLOCK_SIZE );
		iv.random( BLOCK_SIZE );

		checkSpeed( data, key, CryptoMode.ECB, iv );
		checkSpeed( data, key, CryptoMode.CBC, iv );
		checkSpeed( data, key, CryptoMode.CFB, iv );
		checkSpeed( data, key, CryptoMode.OFB, iv );
	}

}
