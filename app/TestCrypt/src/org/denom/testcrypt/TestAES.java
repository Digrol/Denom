// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.testcrypt;

import java.util.Random;
import org.denom.*;
import org.denom.log.*;
import org.denom.crypt.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

public class TestAES
{
	private LogConsole log = new LogConsole();

	static final int ITERATIONS = 3000;
	static final int DATA_SIZE = 2000;

	private static final int BLOCK_SIZE = AES.BLOCK_SIZE;
	static Random rand = new Random( System.nanoTime() );

	// -----------------------------------------------------------------------------------------------------------------
	TestAES()
	{
		Binary IV0 = Bin( 16 );
		check( "80000000000000000000000000000000", IV0, "00000000000000000000000000000000",
				"0EDD33D3C621E546455BD8BA1418BEC8", CryptoMode.ECB, AlignMode.NONE );

		check( "00000000000000000000000000000080", IV0, "00000000000000000000000000000000",
				"172AEAB3D507678ECAF455C12587ADB7", CryptoMode.ECB, AlignMode.NONE );

		check( "000000000000000000000000000000000000000000000000", IV0,
				"80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C", CryptoMode.ECB, AlignMode.NONE );

		check( "0000000000000000000000000000000000000000000000000000000000000000", IV0,
				"80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E", CryptoMode.ECB, AlignMode.NONE );

		checkMonteCarlo( 10000, "00000000000000000000000000000000", "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F" );
		checkMonteCarlo( 10000, "5F060D3716B345C253F6749ABAC10917", "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A" );
		checkMonteCarlo( 10000, "AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114", "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172" );
		checkMonteCarlo( 10000, "28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168" );

		String dataHex = "AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114F3F6752AE8D7831138F041560631B1145A01020304050607";
		String keyHex = "5F060D3716B345C253F6749ABAC10917";
		Binary IV = Bin("000102030405060708090a0b0c0d0e0f");
		
		check( keyHex, IV0, dataHex, "a444a9a4d46eb30cb7ed34d62873a89f8fdf2bf8a54e1aeadd06fd85c9cb46f021ee7cd4f418fa0bb72e9d07c70d5d20",
				CryptoMode.CBC, AlignMode.NONE );
		check( keyHex, IV,  dataHex, "585681354f0e01a86b32f94ebb6a675045d923cf201263c2aaecca2b4de82da0edd74ca5efd654c688f8a58e61955b11",
				CryptoMode.CBC, AlignMode.NONE );
		check( keyHex, IV0, dataHex, "82a1744e8ebbd053ca72362d5e5703264b4182de3208c374b8ac4fa36af9c5e5f4f87d1e3b67963d06acf5eb13914c90",
				CryptoMode.CFB, AlignMode.NONE );
		check( keyHex, IV,  dataHex, "146cbb581d9e12c3333dd9c736fbb9303c8a3eb5185e2809e9d3c28e25cc2d2b6f5c11ee28d6530f72c412b1438a816a",
				CryptoMode.CFB, AlignMode.NONE );
		check( keyHex, IV0, dataHex, "82a1744e8ebbd053ca72362d5e5703261ebf1fdbec05e57b3465b583132f84b43bf95b2c89040ad1677b22d42db69a7a",
				CryptoMode.OFB, AlignMode.NONE );
		check( keyHex, IV,  dataHex, "146cbb581d9e12c3333dd9c736fbb9309ea4c2a7696c84959a2dada49f2f1c5905db1f0cec3a31acbc4701e74ab05e1f",
				CryptoMode.OFB, AlignMode.NONE );

		Binary key = Bin();
		Binary data = Bin();
		Binary iv = Bin();

		
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
	
		measure( data, key, CryptoMode.CBC, iv );

		checkCMAC();

		checkCTR();

		log.writeln( "TestAES - OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	// SP 800-38B - Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
	void checkCMAC()
	{
		// 64 bytes for all test cases
		Binary testData = Bin("6B C1 BE E2  2E 40 9F 96  E9 3D 7E 11  73 93 17 2A"
							+ "AE 2D 8A 57  1E 03 AC 9C  9E B7 6F AC  45 AF 8E 51"
							+ "30 C8 1C 46  A3 5C E4 11  E5 FB C1 19  1A 0A 52 EF"
							+ "F6 9F 24 45  DF 4F 9B 17  AD 2B 41 7B  E6 6C 37 10" );

		//------------------------------------------------------------------
		// Test Key - 128 bit
		Binary key = Bin("2B7E1516 28AED2A6 ABF71588 09CF4F3C");
		// Example #1
		checkCMAC( key, testData.first(  0 ), null, Bin("BB1D6929 E9593728 7FA37D12 9B756746") );
		// Example #2
		checkCMAC( key, testData.first( 16 ), null, Bin("070A16B4 6B4D4144 F79BDD9D D04A287C") );
		// Example #3
		checkCMAC( key, testData.first( 20 ), null, Bin("7D85449E A6EA19C8 23A7BF78 837DFADE") );
		// Example #4
		checkCMAC( key, testData.first( 64 ), null, Bin("51F0BEBF 7E3B9D92 FC497417 79363CFE") );

		//------------------------------------------------------------------
		// Test key - 192 bit
		key = Bin("8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B");

		// Example #1
		checkCMAC( key, testData.first(  0 ), null, Bin("D17DDF46 ADAACDE5 31CAC483 DE7A9367") );
		// Example #2
		checkCMAC( key, testData.first( 16 ), null, Bin("9E99A7BF 31E71090 0662F65E 617C5184") );
		// Example #3
		checkCMAC( key, testData.first( 20 ), null, Bin("3D75C194 ED960704 44A9FA7E C740ECF8") );
		// Example #4
		checkCMAC( key, testData.first( 64 ), null, Bin("A1D5DF0E ED790F79 4D775896 59F39A11") );

		//------------------------------------------------------------------
		// Test key - 256 bit
		key = Bin("603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4");

		// Example #1
		checkCMAC( key, testData.first(  0 ), null, Bin("028962F6 1B7BF89E FC6B551F 4667D983") );
		// Example #2
		checkCMAC( key, testData.first( 16 ), null, Bin("28A7023F 452E8F82 BD4BF28D 8C37C35C") );
		// Example #3
		checkCMAC( key, testData.first( 20 ), null, Bin("156727DC 0878944A 023C1FE0 3BAD6D93") );
		// Example #4
		checkCMAC( key, testData.first( 64 ), null, Bin("E1992190 549F6ED5 696A2C05 6C315410") );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void checkCTR()
	{
		// ISO 10116 Example - Annex D.3.5.1 Counter mode
		checkCTR(
				Bin("2B7E151628AED2A6ABF7158809CF4F3C"),
				Bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"),
				Bin("6BC1BEE22E409F96E93D7E117393172A AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				Bin("874D6191B620E3261BEF6864990DB6CE 9806F66B7970FDFF8617187BB9FFFDFF") );

		// EMV Contactless Book E, Cryptography Worked Examples v1.0.1, 6.1  BDH Key Agreement, Blinding factor validation
		checkCTR(
				Bin("88655CFD79DF9E9DDDEAF9EC0C538DC5"),
				Bin("8000").add( Bin(14) ),
				Bin("8C5AE5C30D3164A755D101C50646F405A06761562EC0CCF940D2B6E67CE2F1F8"),
				Bin("4A7653A86A6AE421DB875BF695F31C8631C1EDB721EBFCBB3057C87DB03EEA7A") );

		checkCTR(
				Bin("88655CFD79DF9E9DDDEAF9EC0C538DC5"),
				Bin("8001").add( Bin(14) ),
				Bin("5A08541333900000151357125413339000001513D29122010000000000005F24032912319F420209789F0702FF005F3401019F810A038C9F06"),
				Bin("0179C459B24A72C6D9359091CFE515E67FC1F8CD1C980DDB5585F82D6C4234A409185CC388AAF6E9D7636FC6E6A1A702F47625A5951A7908D0") );

		checkCTR(
				Bin("88655CFD79DF9E9DDDEAF9EC0C538DC5"),
				Bin("8003").add( Bin(14) ),
				Bin("9F8113081122334455AABBCC"),
				Bin("44BD326A7CF2529D815B0868") );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void checkCTR( Binary key, Binary SV, Binary data, Binary crypt )
	{
		AES aes = new AES( key );
		MUST( aes.cryptCTR( data, SV ).equals( crypt ), "Wrong CTR" );
		MUST( aes.cryptCTR( crypt, SV ).equals( data ), "Wrong CTR" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void checkCMAC( Binary key, Binary data, Binary iv, Binary cmac )
	{
		MUST( new AES( key ).calcCMAC( data, iv ).equals( cmac ), "Wrong CMAC" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void check( String keyHex, Binary IV, String dataHex, String cryptHex, CryptoMode mode, AlignMode alignMode )
	{
		AES aes = new AES( Bin(keyHex) );
		Binary crypt = aes.encrypt( Bin( dataHex ), mode, alignMode, IV );
		MUST( crypt.equals( cryptHex ) );

		Binary data = aes.decrypt( crypt, mode, alignMode, IV );
		MUST( data.equals( dataHex ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void checkMonteCarlo( int iterations, String keyHex, String dataHex, String cryptHex )
	{
		AES aes = new AES( Bin(keyHex) );
		
		Binary block = Bin( dataHex );
		for( int i = 0; i < iterations; ++i )
		{
			aes.encryptBlock( block );
		}
		MUST( block.equals( cryptHex ) );

		for( int i = 0; i < iterations; ++i )
		{
			aes.decryptBlock( block );
		}
		MUST( block.equals( dataHex ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void measure( final Binary data, final Binary key, CryptoMode mode, final Binary iv )
	{
		AES aes = new AES( key );
		long t = Ticker.measureMs( ITERATIONS, () ->
		{
			Binary crypt = aes.encrypt( data, mode, AlignMode.BLOCK, iv );
			aes.decrypt( crypt, mode, AlignMode.BLOCK, iv );
		} );
		log.writeln( "Time AES    : " + t + " ms" );


		AESJce aesJce = new AESJce( key );
		t = Ticker.measureMs( ITERATIONS, () ->
		{
			Binary crypt = aesJce.encrypt( data, mode, AlignMode.BLOCK, iv );
			aesJce.decrypt( crypt, mode, AlignMode.BLOCK, iv );
		} );
		log.writeln( "Time AES JCE: " + t + " ms" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void checkFirstNextLast( final Binary data, final Binary key, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		for ( int i = 0; i < 100; ++i )
		{
			key.random( BLOCK_SIZE );
			iv.random( BLOCK_SIZE );

			AESJce aes_default = new AESJce( key );
			AES aes_stream = new AES( key );

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
			// потоковый AES - разбиваем данные различными способами на куски
			Binary data1 = data.slice( 0, i * BLOCK_SIZE );
			Binary data2 = data.slice( (i    ) * BLOCK_SIZE, BLOCK_SIZE );
			Binary data3 = data.slice( (i + 1) * BLOCK_SIZE, BLOCK_SIZE );
			Binary data4 = data.slice( (i + 2) * BLOCK_SIZE, data.size() - (i + 2) * BLOCK_SIZE );

			Binary encrypt1 = Bin( data1.size() );
			Binary encrypt2 = Bin( data2.size() );
			Binary encrypt3 = Bin( data3.size() );
			Binary encrypt4 = Bin( data4.size() );

			aes_stream.encryptFirst( data1, encrypt1, cryptMode, alignMode, iv );
			aes_stream.encryptNext( data2, encrypt2 );
			aes_stream.encryptNext( data3, encrypt3 );
			aes_stream.encryptLast( data4, encrypt4 );

			Binary crypt_new = encrypt1.add( encrypt2 ).add( encrypt3 ).add( encrypt4 );
			// дефолтный AES
			Binary crypt_old = aes_default.encrypt( data, cryptMode, alignMode, iv );

			MUST( crypt_old.equals( crypt_new ), "OLD_EN!=NEW_EN" );

			//--------------------------------------------------------------------
			// ДЕШИФРОВАНИЕ
			//--------------------------------------------------------------------
			// потоковый AES - разбиваем данные различными способами на куски
			Binary crypt1 = crypt_new.slice( 0, i * BLOCK_SIZE );
			Binary crypt2 = crypt_new.slice( (i    ) * BLOCK_SIZE, BLOCK_SIZE );
			Binary crypt3 = crypt_new.slice( (i + 1) * BLOCK_SIZE, BLOCK_SIZE );
			Binary crypt4 = crypt_new.slice( (i + 2) * BLOCK_SIZE, crypt_new.size() - (i + 2) * BLOCK_SIZE );

			Binary decrypt1 = Bin( crypt1.size() );
			Binary decrypt2 = Bin( crypt2.size() );
			Binary decrypt3 = Bin( crypt3.size() );
			Binary decrypt4 = Bin( crypt4.size() );

			aes_stream.decryptFirst( crypt1, decrypt1, cryptMode, alignMode, iv );
			aes_stream.decryptNext( crypt2, decrypt2 );
			aes_stream.decryptNext( crypt3, decrypt3 );
			aes_stream.decryptLast( crypt4, decrypt4 );

			Binary decrypt_new = decrypt1.add( decrypt2 ).add( decrypt3 ).add( decrypt4 );
			Binary decrypt_old = aes_default.decrypt( crypt_old, cryptMode, alignMode, iv );

			MUST( data.equals( decrypt_old ) );
			MUST( data.equals( decrypt_new ) );
			MUST( decrypt_old.equals( decrypt_new ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	void checkCCSFirstNextLast( final Binary data, final Binary key, CCSMode ccsMode, AlignMode alignMode, final Binary iv )
	{
		for ( int i = 0; i < 99; ++i )
		{
			key.random( BLOCK_SIZE );
			iv.random( BLOCK_SIZE );

			AESJce aes_default = new AESJce( key );
			AES aes_stream = new AES( key );

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
			// потоковый AES - разбиваем данные различными способами на куски
			Binary data1 = data.slice( 0, i * BLOCK_SIZE );
			Binary data2 = data.slice( (i    ) * BLOCK_SIZE, BLOCK_SIZE );
			Binary data3 = data.slice( (i + 1) * BLOCK_SIZE, BLOCK_SIZE );
			Binary data4 = data.slice( (i + 2) * BLOCK_SIZE, data.size() - (i + 2) * BLOCK_SIZE );

			Binary ccs_new = Bin();

			aes_stream.calcCCSfirst( data1, alignMode, ccsMode, iv );
			aes_stream.calcCCSnext( data2 );
			aes_stream.calcCCSnext( data3 );
			aes_stream.calcCCSlast( data4, ccs_new );

			// дефолтный AES
			Binary ccs_old = aes_default.calcCCS( data, alignMode, ccsMode, iv );

			MUST( ccs_old.equals( ccs_new ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	void checkNonStream( final Binary data, final Binary key, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		for ( int i = 0; i < 100; ++i )
		{
			key.random( BLOCK_SIZE );
			iv.random( BLOCK_SIZE );

			AESJce aes_default = new AESJce( key );
			AES aes_stream = new AES( key );

			key.random( BLOCK_SIZE );
			aes_default.setKey( key );
			aes_stream.setKey( key );

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
			Binary crypt_new = aes_stream.encrypt( data, cryptMode, alignMode, iv );
			Binary crypt_old = aes_default.encrypt( data, cryptMode, alignMode, iv );

			MUST( crypt_old.equals( crypt_new ) );

			Binary decrypt_new = aes_stream.decrypt( crypt_old, cryptMode, alignMode, iv );
			Binary decrypt_old = aes_default.decrypt( crypt_old, cryptMode, alignMode, iv );

			MUST( decrypt_old.equals( decrypt_new ) );

			MUST( data.equals( decrypt_old ) );
			MUST( data.equals( decrypt_new ) );
			//--------------------------------------------------------------------

			//--------------------------------------------------------------------
			// ВЫЧИСЛЕНИЕ КОНТРОЛЬНОЙ СУММЫ
			Binary ccs_old = aes_default.calcCCS( data, AlignMode.BLOCK, CCSMode.CLASSIC, iv );
			Binary ccs_new = aes_stream.calcCCS( data, AlignMode.BLOCK, CCSMode.CLASSIC, iv );

			MUST( ccs_old.equals( ccs_new ) );

			ccs_old = aes_default.calcCCS( data, AlignMode.BLOCK, CCSMode.FAST, iv );
			ccs_new = aes_stream.calcCCS( data, AlignMode.BLOCK, CCSMode.FAST, iv );

			MUST( ccs_old.equals( ccs_new ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestAES();
	}

}