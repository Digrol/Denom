// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.crypt;

import java.util.Arrays;

import org.denom.Binary;

import static org.denom.Ex.*;
import static org.denom.Binary.*;

/**
 * Шифр DES.
 */
public class DES
{
	public static final int BLOCK_SIZE = 8;
	public static final int KEY_SIZE = 8;

	// -----------------------------------------------------------------------------------------------------------------
	private static final int[] ODD_PARITY =
	{
		  1,   1,   2,   2,   4,   4,   7,   7,   8,   8,  11,  11,  13,  13,  14,  14,
		 16,  16,  19,  19,  21,  21,  22,  22,  25,  25,  26,  26,  28,  28,  31,  31,
		 32,  32,  35,  35,  37,  37,  38,  38,  41,  41,  42,  42,  44,  44,  47,  47,
		 49,  49,  50,  50,  52,  52,  55,  55,  56,  56,  59,  59,  61,  61,  62,  62,
		 64,  64,  67,  67,  69,  69,  70,  70,  73,  73,  74,  74,  76,  76,  79,  79,
		 81,  81,  82,  82,  84,  84,  87,  87,  88,  88,  91,  91,  93,  93,  94,  94,
		 97,  97,  98,  98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
		112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
		128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
		145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
		161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
		176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
		193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
		208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
		224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
		241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254
	};

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Установить биты нечётности в ключе.
	 * @param key
	 * @return - ссылка на key.
	 */
	public static Binary setOddParityBits( Binary key )
	{
		for( int i = 0; i < key.size(); ++i )
		{
			key.set( i, ODD_PARITY[ key.get( i ) ] );
		}
		return key;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор. Ключ задать позже.
	 */
	public DES()
	{
		this( Bin(KEY_SIZE) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param key - secret key [8 байт]
	 */
	public DES( final Binary key )
	{
		setKey( key );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать ключ.
	 * @param key - Ключ [8 байт].
	 */
	public DES setKey( final Binary key )
	{
		setKey( key, 0 );
		return this;
	}

	/**
	 * Задать ключ.
	 * @param offset - смещение в массиве key, по которому лежит ключ.
	 */
	public DES setKey( final Binary key, int offset )
	{
		MUST( (offset + KEY_SIZE) <= key.size(), "Wrong key size" );
		mKey.assign( key, offset, KEY_SIZE );
		initKey();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return copy of cipher key.
	 */
	public Binary getKey()
	{
		return mKey.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сгенерировать случайный ключ. Ключ будет установлен в качестве текущего.
	 */
	public Binary generateKey()
	{
		Binary akey = new Binary().randomSecure( KEY_SIZE );
		setOddParityBits( akey );
		setKey( akey );
		return akey;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные.
	 * @param data Входные данные
	 * @param cryptMode Режим шифрования
	 * @param alignMode Режим выравнивания
	 * @param iv Входной начальный вектор
	 * @return зашифрованные данные
	 */
	public Binary encrypt( final Binary data, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be 8 bytes." );

		Binary padded = Bin().reserve( data.size() + BLOCK_SIZE );
		padded.add( data );
		Crypt.pad( padded, BLOCK_SIZE, alignMode );

		MUST( (padded.size() & ( BLOCK_SIZE - 1 ) ) == 0, "Wrong data. Must be multiple of 8 bytes" );
		MUST( !padded.empty(), "No data" );

		encryptFirst( Bin(), Bin(), cryptMode, alignMode, iv);
		encryptNext( padded, padded );

		return padded;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные с нулевым начальным вектором.
	 * @param data Входные данные
	 * @param cryptMode Режим шифрования
	 * @param alignMode Режим выравнивания
	 * @return Зашифрованные данные
	 */
	public Binary encrypt( final Binary data, CryptoMode cryptMode, AlignMode alignMode )
	{
		return encrypt( data, cryptMode, alignMode, IV0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные в потоковом режиме: Первый шаг.
	 * @param data - Массив входных данных (нулевого размера, или кратный [8 байт])
	 * @param crypt - Массив для выходных данных (того же размера как и data)
	 * @param cryptMode - Режим шифрования.
	 * @param alignMode - Режим выравнивания.
	 * @param iv - начальный вектор
	 */
	public void encryptFirst( final Binary data, Binary crypt, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be 8 bytes." );

		this.crypt_mode = cryptMode;
		this.align_mode = alignMode;
		this.temp_IV = (cryptMode == CryptoMode.ECB) ? IV0.clone() : iv.clone();

		encryptNext( data, crypt );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные в потоковом режиме: Промежуточные шаги.
	 * @param data - Массив входных данных (нулевого размера, или кратный [8 байт]).
	 * @param crypt - Массив для выходных данных (того же размера как и data).
	 */
	public void encryptNext( final Binary data, Binary crypt )
	{
		MUST( crypt.size() == data.size(), "data and crypt must be equal size" );
		MUST( (data.size() & (BLOCK_SIZE - 1)) == 0, "Wrong data. Must be multiple of 8 bytes" );

		for( int i = 0; i < data.size(); i += BLOCK_SIZE )
		{
			temp_block.assign( data, i, BLOCK_SIZE );

			switch( crypt_mode )
			{
				case ECB:
					encryptBlock( temp_block );
					break;

				case CBC:
					temp_block.xor( temp_IV );
					encryptBlock( temp_block );
					temp_IV.assign( temp_block );
					break;

				case CFB:
					encryptBlock( temp_IV );
					temp_block.xor( temp_IV );
					temp_IV.assign( temp_block );
					break;

				case OFB:
					encryptBlock( temp_IV );
					temp_block.xor( temp_IV );
					break;
			}

			System.arraycopy( temp_block.getDataRef(), 0, crypt.getDataRef(), i, BLOCK_SIZE );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные в потоковом режиме: Последний шаг.
	 * @param data - Массив входных данных (кратный [8 байт] если AlignMode.BLOCK, любого размера если
	 * AlignMode.NONE)
	 * @param crypt - Массив для выходных данных (того же размера как и data)</br>
	 * при AlignMode.BLOCK меняет размер crypt.data
	 */
	public void encryptLast( final Binary data, Binary crypt )
	{
		if( align_mode == AlignMode.BLOCK )
		{
			crypt.assign( encrypt( data, crypt_mode, align_mode, temp_IV ) );
		}
		else
		{
			encryptNext( data, crypt );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные.
	 * @param crypt Входные зашифрованные данные
	 * @param cryptMode Режим дешифрования
	 * @param alignMode Режим выравнивания
	 * @param iv Входной начальный вектор
	 * @return Расшифрованные данные
	 */
	public Binary decrypt( final Binary crypt, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be 8 bytes." );
		MUST( ( crypt.size() & (BLOCK_SIZE - 1) ) == 0, "Wrong data. Must be multiple of 8 bytes" );

		Binary data = Bin( crypt.size() );
		decryptFirst( Bin(), Bin(), cryptMode, alignMode, iv);
		decryptNext( crypt, data );
		Crypt.unPad( data, BLOCK_SIZE, alignMode );

		return data;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные с нулевым начальным вектором.
	 * @param crypt Входные зашифрованные данные
	 * @param cryptMode Режим дешифрования
	 * @param alignMode Режим выравнивания
	 * @return Расшифрованные данные
	 */
	public Binary decrypt( final Binary crypt, CryptoMode cryptMode, AlignMode alignMode )
	{
		return decrypt( crypt, cryptMode, alignMode, IV0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные в потоковом режиме: Первый шаг.
	 * @param crypt Массив входных данных (нулевого размера, или кратный [8 байт])
	 * @param data Массив для выходных данных (того же размера как и crypt)
	 * @param cryptMode Режим шифрования
	 * @param alignMode Режим выравнивания
	 * @param iv Начальный вектор
	 */
	public void decryptFirst( final Binary crypt, Binary data, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be 8 bytes." );

		this.crypt_mode = cryptMode;
		this.align_mode = alignMode;
		this.temp_IV = (cryptMode == CryptoMode.ECB) ? IV0.clone() : iv.clone();

		decryptNext( crypt, data );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные в потоковом режиме: Промежуточные шаги.
	 * @param crypt - Массив входных данных (нулевого размера, или кратный [8 байт])
	 * @param data - Массив для выходных данных (того же размера как и crypt)
	 */
	public void decryptNext( final Binary crypt, Binary data )
	{
		MUST( crypt.size() == data.size(), "crypt and data must be equal size" );
		MUST( (crypt.size() & (BLOCK_SIZE - 1)) == 0, "Wrong data. Must be multiple of 8 bytes" );

		for( int i = 0; i < crypt.size(); i += BLOCK_SIZE )
		{
			temp_block.assign( crypt, i, BLOCK_SIZE );

			switch( crypt_mode )
			{
				case ECB:
					decryptBlock( temp_block );
					break;

				case CBC:
					prev_IV.assign( temp_block );
					decryptBlock( temp_block );
					temp_block.xor( temp_IV );
					temp_IV.assign( prev_IV );
					break;

				case CFB:
					prev_IV.assign( temp_block );
					encryptBlock( temp_IV );
					temp_block.xor( temp_IV );
					temp_IV.assign( prev_IV );
					break;

				case OFB:
					encryptBlock( temp_IV );
					temp_block.xor( temp_IV );
					break;
			}

			data.set( i, temp_block, 0, BLOCK_SIZE );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные в потоковом режиме: Последний шаг.
	 * @param crypt Массив входных данных (кратный [8 байт])
	 * @param data Массив для выходных данных (того же размера как и crypt). При AlignMode.BLOCK
	 * меняет размер data.data
	 */
	public void decryptLast( final Binary crypt, Binary data )
	{
		if( align_mode == AlignMode.BLOCK )
		{
			data.assign( decrypt( crypt, crypt_mode, align_mode, temp_IV ) );
		}
		else
		{
			decryptNext( crypt, data );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить криптографическую контрольную сумму.
	 * @param data - Входные данные
	 * @param alignMode - Режим выравнивания
	 * @param ccsMode - Режим контрольной суммы
	 * @param iv - Начальный вектор
	 * @return Контрольная сумма
	 */
	public Binary calcCCS( final Binary data, AlignMode alignMode, CCSMode ccsMode, final Binary iv )
	{
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be 8 bytes." );

		Binary crypt = encrypt( data, CryptoMode.CBC, alignMode, iv );
		return crypt.slice( crypt.size() - BLOCK_SIZE, BLOCK_SIZE );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить криптографическую контрольную сумму с нулевым начальным вектором.
	 * @param data - Входные данные
	 * @param alignMode - Режим выравнивания
	 * @param ccsMode - Режим контрольной суммы
	 * @return Контрольная сумма
	 */
	public Binary calcCCS( final Binary data, AlignMode alignMode, CCSMode ccsMode )
	{
		return calcCCS( data, alignMode, ccsMode, IV0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить криптографическую контрольную сумму в потоковом режиме: Первый шаг.</br>
	 * Данные должны быть кратны [8 байт].
	 * @param data Входной массив
	 * @param alignMode Режим выравнивания
	 * @param ccsMode Режим контрольной суммы
	 * @param iv Начальный вектор
	 */
	public void calcCCSfirst( final Binary data, AlignMode alignMode, CCSMode ccsMode, final Binary iv )
	{
		Binary temp = Bin( data.size() );
		encryptFirst( data, temp, CryptoMode.CBC, alignMode, iv );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить криптографическую контрольную сумму в потоковом режиме: Промежуточные шаги.</br>
	 * Данные должны быть кратны [8 байт].
	 * @param data Входной массив
	 */
	public void calcCCSnext( final Binary data )
	{
		Binary temp = Bin( data.size() );
		encryptNext( data, temp );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить криптографическую контрольную сумму в потоковом режиме: Последний шаг.
	 * @param data Входной массив
	 * @param ccs Выходной массив
	 */
	public void calcCCSlast( final Binary data, Binary ccs )
	{
		Binary temp = Bin( data.size() );
		encryptLast( data, temp );

		ccs.assign( temp, temp.size() - BLOCK_SIZE, BLOCK_SIZE );
	}


	// -----------------------------------------------------------------------------------------------------------------
	public void encryptBlock( Binary block )
	{
		processBlock( kEnc, block, 0, block, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void decryptBlock( Binary block )
	{
		processBlock( kDec, block, 0, block, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary temp_IV = new Binary( BLOCK_SIZE );

	private CryptoMode crypt_mode;
	private AlignMode align_mode;
	private Binary temp_block = new Binary( BLOCK_SIZE );
	private Binary prev_IV = new Binary( BLOCK_SIZE );

	// 8-байтный ключ
	private Binary mKey = Bin( 8 );

	// -----------------------------------------------------------------------------------------------------------------
	// CONSTANTS
	// -----------------------------------------------------------------------------------------------------------------
	private static final Binary IV0 = Bin( 8 );

	private static final byte[] ROT = { 1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28 };

	private static final byte[] PC1 = {
		56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
		 9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
		62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
		13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3
	};

	private static final byte[] PC2 = {
		13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
		22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
		40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
		43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
	};

	private static final int[] SP1 = {
		0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404, 0x00000004, 0x00010000,
		0x00000400, 0x01010400, 0x01010404, 0x00000400, 0x01000404, 0x01010004, 0x01000000, 0x00000004,
		0x00000404, 0x01000400, 0x01000400, 0x00010400, 0x00010400, 0x01010000, 0x01010000, 0x01000404,
		0x00010004, 0x01000004, 0x01000004, 0x00010004, 0x00000000, 0x00000404, 0x00010404, 0x01000000,
		0x00010000, 0x01010404, 0x00000004, 0x01010000, 0x01010400, 0x01000000, 0x01000000, 0x00000400,
		0x01010004, 0x00010000, 0x00010400, 0x01000004, 0x00000400, 0x00000004, 0x01000404, 0x00010404,
		0x01010404, 0x00010004, 0x01010000, 0x01000404, 0x01000004, 0x00000404, 0x00010404, 0x01010400,
		0x00000404, 0x01000400, 0x01000400, 0x00000000, 0x00010004, 0x00010400, 0x00000000, 0x01010004
	};
	
	private static final int[] SP2 = {
		0x80108020, 0x80008000, 0x00008000, 0x00108020, 0x00100000, 0x00000020, 0x80100020, 0x80008020,
		0x80000020, 0x80108020, 0x80108000, 0x80000000, 0x80008000, 0x00100000, 0x00000020, 0x80100020,
		0x00108000, 0x00100020, 0x80008020, 0x00000000, 0x80000000, 0x00008000, 0x00108020, 0x80100000,
		0x00100020, 0x80000020, 0x00000000, 0x00108000, 0x00008020, 0x80108000, 0x80100000, 0x00008020,
		0x00000000, 0x00108020, 0x80100020, 0x00100000, 0x80008020, 0x80100000, 0x80108000, 0x00008000,
		0x80100000, 0x80008000, 0x00000020, 0x80108020, 0x00108020, 0x00000020, 0x00008000, 0x80000000,
		0x00008020, 0x80108000, 0x00100000, 0x80000020, 0x00100020, 0x80008020, 0x80000020, 0x00100020,
		0x00108000, 0x00000000, 0x80008000, 0x00008020, 0x80000000, 0x80100020, 0x80108020, 0x00108000
	};
	
	private static final int[] SP3 = {
		0x00000208, 0x08020200, 0x00000000, 0x08020008, 0x08000200, 0x00000000, 0x00020208, 0x08000200,
		0x00020008, 0x08000008, 0x08000008, 0x00020000, 0x08020208, 0x00020008, 0x08020000, 0x00000208,
		0x08000000, 0x00000008, 0x08020200, 0x00000200, 0x00020200, 0x08020000, 0x08020008, 0x00020208,
		0x08000208, 0x00020200, 0x00020000, 0x08000208, 0x00000008, 0x08020208, 0x00000200, 0x08000000,
		0x08020200, 0x08000000, 0x00020008, 0x00000208, 0x00020000, 0x08020200, 0x08000200, 0x00000000,
		0x00000200, 0x00020008, 0x08020208, 0x08000200, 0x08000008, 0x00000200, 0x00000000, 0x08020008,
		0x08000208, 0x00020000, 0x08000000, 0x08020208, 0x00000008, 0x00020208, 0x00020200, 0x08000008,
		0x08020000, 0x08000208, 0x00000208, 0x08020000, 0x00020208, 0x00000008, 0x08020008, 0x00020200
	};
	
	private static final int[] SP4 = {
		0x00802001, 0x00002081, 0x00002081, 0x00000080, 0x00802080, 0x00800081, 0x00800001, 0x00002001,
		0x00000000, 0x00802000, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00800080, 0x00800001,
		0x00000001, 0x00002000, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002001, 0x00002080,
		0x00800081, 0x00000001, 0x00002080, 0x00800080, 0x00002000, 0x00802080, 0x00802081, 0x00000081,
		0x00800080, 0x00800001, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00000000, 0x00802000,
		0x00002080, 0x00800080, 0x00800081, 0x00000001, 0x00802001, 0x00002081, 0x00002081, 0x00000080,
		0x00802081, 0x00000081, 0x00000001, 0x00002000, 0x00800001, 0x00002001, 0x00802080, 0x00800081,
		0x00002001, 0x00002080, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002000, 0x00802080
	};

	private static final int[] SP5 = {
		0x00000100, 0x02080100, 0x02080000, 0x42000100, 0x00080000, 0x00000100, 0x40000000, 0x02080000,
		0x40080100, 0x00080000, 0x02000100, 0x40080100, 0x42000100, 0x42080000, 0x00080100, 0x40000000,
		0x02000000, 0x40080000, 0x40080000, 0x00000000, 0x40000100, 0x42080100, 0x42080100, 0x02000100,
		0x42080000, 0x40000100, 0x00000000, 0x42000000, 0x02080100, 0x02000000, 0x42000000, 0x00080100,
		0x00080000, 0x42000100, 0x00000100, 0x02000000, 0x40000000, 0x02080000, 0x42000100, 0x40080100,
		0x02000100, 0x40000000, 0x42080000, 0x02080100, 0x40080100, 0x00000100, 0x02000000, 0x42080000,
		0x42080100, 0x00080100, 0x42000000, 0x42080100, 0x02080000, 0x00000000, 0x40080000, 0x42000000,
		0x00080100, 0x02000100, 0x40000100, 0x00080000, 0x00000000, 0x40080000, 0x02080100, 0x40000100
	};

	private static final int[] SP6 = {
		0x20000010, 0x20400000, 0x00004000, 0x20404010, 0x20400000, 0x00000010, 0x20404010, 0x00400000,
		0x20004000, 0x00404010, 0x00400000, 0x20000010, 0x00400010, 0x20004000, 0x20000000, 0x00004010,
		0x00000000, 0x00400010, 0x20004010, 0x00004000, 0x00404000, 0x20004010, 0x00000010, 0x20400010,
		0x20400010, 0x00000000, 0x00404010, 0x20404000, 0x00004010, 0x00404000, 0x20404000, 0x20000000,
		0x20004000, 0x00000010, 0x20400010, 0x00404000, 0x20404010, 0x00400000, 0x00004010, 0x20000010,
		0x00400000, 0x20004000, 0x20000000, 0x00004010, 0x20000010, 0x20404010, 0x00404000, 0x20400000,
		0x00404010, 0x20404000, 0x00000000, 0x20400010, 0x00000010, 0x00004000, 0x20400000, 0x00404010,
		0x00004000, 0x00400010, 0x20004010, 0x00000000, 0x20404000, 0x20000000, 0x00400010, 0x20004010
	};

	private static final int[] SP7 = {
		0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802, 0x00200802, 0x04200800,
		0x04200802, 0x00200000, 0x00000000, 0x04000002, 0x00000002, 0x04000000, 0x04200002, 0x00000802,
		0x04000800, 0x00200802, 0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
		0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002, 0x04000000, 0x00200800,
		0x04000000, 0x00200800, 0x00200000, 0x04000802, 0x04000802, 0x04200002, 0x04200002, 0x00000002,
		0x00200002, 0x04000000, 0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
		0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000, 0x00000002, 0x04200802,
		0x00000000, 0x00200802, 0x04200000, 0x00000800, 0x04000002, 0x04000800, 0x00000800, 0x00200002
	};

	private static final int[] SP8 = {
		0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040, 0x00000040, 0x10000000,
		0x00040040, 0x10040000, 0x10041040, 0x00041000, 0x10041000, 0x00041040, 0x00001000, 0x00000040,
		0x10040000, 0x10000040, 0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
		0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000, 0x00041040, 0x00040000,
		0x00041040, 0x00040000, 0x10041000, 0x00001000, 0x00000040, 0x10040040, 0x00001000, 0x00041040,
		0x10001000, 0x00000040, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
		0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0x00000000,
		0x10041040, 0x00041000, 0x00041000, 0x00001040, 0x00001040, 0x00040040, 0x10000000, 0x10041000
	};

	// -----------------------------------------------------------------------------------------------------------------
	private int[] kEnc = new int[ 32 ];
	private int[] kDec = new int[ 32 ];
	private boolean[] pcM = new boolean[ 56 ];
	private boolean[] pcR = new boolean[ 56 ];

	// -----------------------------------------------------------------------------------------------------------------
	private void initKey()
	{
		Arrays.fill( kEnc, 0 );
		Arrays.fill( kDec, 0 );
		Arrays.fill( pcM, false );
		Arrays.fill( pcR, false );

		for( int j = 0; j < 56; j++ )
		{
			int l = PC1[ j ];
			pcM[ j ] = (mKey.get( l >>> 3 ) & (1 << (7 - l & 0x07))) != 0;
		}

		for( int i = 0; i < 16; i++ )
		{
			for( int j = 0; j < 28; j++ )
			{
				int l = j + ROT[ i ];
				pcR[ j ] = ( l < 28 ) ? pcM[ l ] : pcM[ l - 28 ];
			}

			for( int j = 28; j < 56; j++ )
			{
				int l = j + ROT[ i ];
				pcR[ j ] = ( l < 56 ) ? pcM[ l ] : pcM[ l - 28 ];
			}

			for( int j = 0; j < 24; j++ )
			{
				if( pcR[ PC2[ j ] ] )
					kEnc[ i << 1 ] |= 1 << (23 - j);

				if( pcR[ PC2[ j + 24 ] ] )
					kEnc[ (i << 1) + 1 ] |= 1 << (23 - j);
			}
		}

		for( int i = 0; i != 32; i += 2 )
		{
			int i1 = kEnc[ i ];
			int i2 = kEnc[ i + 1 ];
			kEnc[ i ]     = ((i1 & 0x00fc0000) << 6) | ((i1 & 0x00000fc0) << 10) | ((i2 & 0x00fc0000) >>> 10) | ((i2 & 0x00000fc0) >>> 6);
			kEnc[ i + 1 ] = ((i1 & 0x0003f000) << 12) | ((i1 & 0x0000003f) << 16) | ((i2 & 0x0003f000) >>> 4) | (i2 & 0x0000003f);
		}

		for( int i = 0; i < 32; i += 2)
		{
			kDec[ 30 - i ] = kEnc[ i ];
			kDec[ 31 - i ] = kEnc[ i + 1 ];
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processBlock( int[] K, Binary data, int dataOffset, Binary result, int resultOffset )
	{
		int l = data.getIntBE( dataOffset );
		int r = data.getIntBE( dataOffset + 4 );

		{
			// Initial permutation
			int t = ((l >>> 4) ^ r) & 0x0f0f0f0f;
			r ^= t;
			l ^= t << 4;
			t = ((l >>> 16) ^ r) & 0x0000ffff;
			r ^= t;
			l ^= t << 16;
			t = ((r >>> 2) ^ l) & 0x33333333;
			l ^= t;
			r ^= t << 2;
			t = ((r >>> 8) ^ l) & 0x00ff00ff;
			l ^= t;
			r ^= t << 8;
			r = (r << 1) | (r >>> 31);
			t = (l ^ r) & 0xaaaaaaaa;
			l ^= t;
			r ^= t;
			l = (l << 1) | (l >>> 31);
		}

		for( int i = 0; i < 8; ++i )
		{
			int t = (r << 28) | (r >>> 4);
			t ^= K[ i * 4 + 0 ];
			int f = SP7[ t & 0x3f ];
			f |= SP5[ (t >>> 8) & 0x3f ];
			f |= SP3[ (t >>> 16) & 0x3f ];
			f |= SP1[ (t >>> 24) & 0x3f ];
			t = r ^ K[ i * 4 + 1 ];
			f |= SP8[ t & 0x3f ];
			f |= SP6[ (t >>> 8) & 0x3f ];
			f |= SP4[ (t >>> 16) & 0x3f ];
			f |= SP2[ (t >>> 24) & 0x3f ];
			l ^= f;
			t = (l << 28) | (l >>> 4);
			t ^= K[ i * 4 + 2 ];
			f = SP7[ t & 0x3f ];
			f |= SP5[ (t >>> 8) & 0x3f ];
			f |= SP3[ (t >>> 16) & 0x3f ];
			f |= SP1[ (t >>> 24) & 0x3f ];
			t = l ^ K[ i * 4 + 3 ];
			f |= SP8[ t & 0x3f ];
			f |= SP6[ (t >>> 8) & 0x3f ];
			f |= SP4[ (t >>> 16) & 0x3f ];
			f |= SP2[ (t >>> 24) & 0x3f ];
			r ^= f;
		}

		// final permutation
		{
			r = (r << 31) | (r >>> 1);
			int t = (l ^ r) & 0xaaaaaaaa;
			l ^= t;
			r ^= t;
			l = (l << 31) | (l >>> 1);
			t = ((l >>> 8) ^ r) & 0x00ff00ff;
			r ^= t;
			l ^= (t << 8);
			t = ((l >>> 2) ^ r) & 0x33333333;
			r ^= t;
			l ^= (t << 2);
			t = ((r >>> 16) ^ l) & 0x0000ffff;
			l ^= t;
			r ^= (t << 16);
			t = ((r >>> 4) ^ l) & 0x0f0f0f0f;
			l ^= t;
			r ^= (t << 4);
		}

		result.setInt( resultOffset, r );
		result.setInt( resultOffset + 4, l );
	}

}