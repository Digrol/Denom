package org.denom.testcrypt.cipher;

import org.denom.Binary;
import org.denom.crypt.hash.GOST3411_94;
import org.denom.crypt.hash.GOST_SBox;
import org.denom.crypt.blockcipher.*;
import org.denom.crypt.blockcipher.gost.*;

import static org.denom.Ex.*;
import static org.denom.Binary.Bin;
import static org.denom.testcrypt.cipher.CheckCipher.*;

public class TestGOST28147
{
	// -----------------------------------------------------------------------------------------------------------------
	byte TestSBox[] = {
		0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
		0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
		0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
		0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
		0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
		0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
		0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
		0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0
	};

	// -----------------------------------------------------------------------------------------------------------------
	byte[] TestSBox_1 = {
		0xE, 0x3, 0xC, 0xD, 0x1, 0xF, 0xA, 0x9, 0xB, 0x6, 0x2, 0x7, 0x5, 0x0, 0x8, 0x4,
		0xD, 0x9, 0x0, 0x4, 0x7, 0x1, 0x3, 0xB, 0x6, 0xC, 0x2, 0xA, 0xF, 0xE, 0x5, 0x8,
		0x8, 0xB, 0xA, 0x7, 0x1, 0xD, 0x5, 0xC, 0x6, 0x3, 0x9, 0x0, 0xF, 0xE, 0x2, 0x4,
		0xD, 0x7, 0xC, 0x9, 0xF, 0x0, 0x5, 0x8, 0xA, 0x2, 0xB, 0x6, 0x4, 0x3, 0x1, 0xE,
		0xB, 0x4, 0x6, 0x5, 0x0, 0xF, 0x1, 0xC, 0x9, 0xE, 0xD, 0x8, 0x3, 0x7, 0xA, 0x2,
		0xD, 0xF, 0x9, 0x4, 0x2, 0xC, 0x5, 0xA, 0x6, 0x0, 0x3, 0x8, 0x7, 0xE, 0x1, 0xB,
		0xF, 0xE, 0x9, 0x5, 0xB, 0x2, 0x1, 0x8, 0x6, 0x0, 0xD, 0x3, 0x4, 0x7, 0xC, 0xA,
		0xA, 0x3, 0xE, 0x2, 0x0, 0x1, 0x4, 0x6, 0xB, 0x8, 0xC, 0x7, 0xD, 0x5, 0xF, 0x9
	};

	// -----------------------------------------------------------------------------------------------------------------
	TestGOST28147()
	{
		String block0 = "0000000000000000";
		String IV1 = "1234567890abcdef";

		checkCipher( new GOST28147(), "546d203368656c326973652073736e62206167796967747473656865202c3d73",
			block0, "1b0bbc32cebcab42" );

		checkCipher( new CBCBlockCipher(new GOST28147()), "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF", IV1,
			"bc350e71aac5f5c2", "d35ab653493b49f5" );

		checkCipher( new GOFBBlockCipher(new GOST28147()), "0011223344556677889900112233445566778899001122334455667788990011", IV1,
			"bc350e71aa11345709acde", "8824c124c4fd14301fb1e8" );

		checkCipher( new CFBBlockCipher(new GOST28147(), 64), "aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5", "aafd12f659cae634",
			"000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f", "29b7083e0a6d955ca0ec5b04fdb4ea41949f1dd2efdf17baffc1780b031f3934" );

		// ---------------------------------------------------------------------------------------

		String key1 = "546d203368656c326973652073736e62206167796967747473656865202c3d73";
		checkCipher( new CFBBlockCipher(new GOST28147(GOST_SBox.D_Test), 64), key1, IV1, block0, "b587f7a0814c911d" );
		checkCipher( new CFBBlockCipher(new GOST28147(GOST_SBox.E_Test), 64), key1, IV1, block0, "e8287f53f991d52b" );
		checkCipher( new CFBBlockCipher(new GOST28147(GOST_SBox.E_A   ), 64), key1, IV1, block0, "c41009dba22ebe35" );
		checkCipher( new CFBBlockCipher(new GOST28147(GOST_SBox.E_B   ),  8), key1, IV1, block0, "80d8723fcd3aba28" );
		checkCipher( new CFBBlockCipher(new GOST28147(GOST_SBox.E_C   ),  8), key1, IV1, block0, "739f6f95068499b5" );
		checkCipher( new CFBBlockCipher(new GOST28147(GOST_SBox.E_D   ),  8), key1, IV1, block0, "4663f720f4340f57" );
		checkCipher( new CFBBlockCipher(new GOST28147(GOST_SBox.D_A   ),  8), key1, IV1, block0, "5bb0a31d218ed564" );
		checkCipher( new CFBBlockCipher(new GOST28147(TestSBox        ),  8), key1, IV1, block0, "c3af96ef788667c5" );

		checkCipher( new GOFBBlockCipher( new GOST28147(GOST_SBox.E_A) ), "4ef72b778f0b0bebeef4f077551cb74a927b470ad7d7f2513454569a247e989d", IV1,
			"bc350e71aa11345709acde", "1bcc2282707c676fb656dc" );

		// ---------------------------------------------------------------------------------------

		String key2 = "0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993";

		checkCipher( new GOFBBlockCipher(new GOST28147(TestSBox_1)), key2, "8001069080010690",
			"094C912C5EFDD703D42118971694580B", "2707B58DF039D1A64460735FFE76D55F" );

		checkCipher( new GOFBBlockCipher(new GOST28147(TestSBox_1)), key2, "800107A0800107A0",
			"FE780800E0690083F20C010CF00C0329", "9AF623DFF948B413B53171E8D546188D" );

		checkCipher( new GOFBBlockCipher(new GOST28147(TestSBox_1)), key2, "8001114080011140",
			"D1088FD8C0A86EE8F1DCD1088FE8C058", "62A6B64D12253BCD8241A4BB0CFD3E7C" );

		checkCipher( new GOFBBlockCipher(new GOST28147(TestSBox_1)), key2, "80011A3080011A30",
			"D431FACD011C502C501B500A12921090", "07313C89D302FF73234B4A0506AB00F3" );

		// ---------------------------------------------------------------------------------------

		String key3 = new GOST3411_94().calc( Bin( "0123456789abcdef" ) ).Hex();
		checkCipher( new GOST28147(GOST_SBox.E_A), key3,
				"4e6f77206973207468652074696d6520666f7220616c6c20", "8ad3c8f56b27ff1fbd46409359bdc796bc350e71aac5f5c0" );

		checkCipher( new CFBBlockCipher(new GOST28147( GOST_SBox.E_A ), 64), key3, IV1,
				"bc350e71aac5f5c2", "0ebbbafcf38f14a5" );

		checkCipher( new GOFBBlockCipher(new GOST28147( GOST_SBox.E_A )), key3, IV1,
				"bc350e71aa11345709acde", "1bcc2282707c676fb656dc" );

		String key4 = new GOST3411_94().calc( Bin( "aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5" ) ).Hex();
		checkCipher( new CFBBlockCipher(new GOST28147( GOST_SBox.E_A ), 64), key4, "aafd12f659cae634",
				"000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f", "64988982819f0a1655e226e19ecad79d10cc73bac95c5d7da034786c12294225" );

		// ---------------------------------------------------------------------------------------

		GOST28147Mac mac = new GOST28147Mac().setKey( Bin("6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49") );

		Binary out = Bin( 4 );
		Binary data = Bin( "7768617420646f2079612077616e7420666f72206e6f7468696e673f" );
		mac.update( data.getDataRef(), 0, data.size() );
		mac.doFinal( out.getDataRef(), 0 );
		MUST( out.equals( "93468a46" ) );

		System.out.println( getClass().getSimpleName() + ": OK" );
	};

	public static void main( String[] args )
	{
		new TestGOST28147();
	}
}
