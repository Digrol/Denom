// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.crypt;

import org.denom.Binary;
import org.denom.crypt.hash.SHA256;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

/**
 * BlockCipher AES (Advanced Encryption Standard) aka Rijndael.
 */
public class AES 
{
	public static final int BLOCK_SIZE = 16;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор. Ключ задать позже.
	 */
	public AES()
	{
		this( Bin(16) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public AES( Binary key )
	{
		setKey( key );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void checkKeySize( int key_size )
	{
		MUST( (key_size == 16) || (key_size == 24) || (key_size == 32), "Invalid AES key size" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать ключ шифрования.
	 * @param key Ключ [16 или 24 или 32 байт]
	 */
	public AES setKey( final Binary key )
	{
		checkKeySize( key.size() );
		m_key = key.clone();

		Nk = key.size() >>> 2;
		Nr = Nk + 6;
		Nw = 4 * (Nr + 1);
		rek = new int[ Nw ];
		rdk = new int[ Nw ];
		expandKey( m_key );
		invertKey();

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить значение ключа шифрования.
	 * 
	 * @return Копия значения ключа
	 */
	public Binary getKey()
	{
		return m_key.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сгенерировать случайный ключ. Ключ будет установлен в качестве текущего.
	 */
	public Binary generateKey( int key_size )
	{
		checkKeySize( key_size );
		Binary akey = new SHA256().calc( new Binary().randomSecure( 32 ) ).slice( 0, key_size );
		setKey( akey );
		return akey;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary generateKey()
	{
		return generateKey( 16 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные.
	 * 
	 * @param data Входные данные
	 * @param cryptMode Режим шифрования
	 * @param alignMode Режим выравнивания
	 * @param iv Входной начальный вектор
	 * @return Зашифрованные данные
	 */
	public Binary encrypt( final Binary data, CryptoMode cryptMode, AlignMode alignMode, Binary iv )
	{
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be BLOCK_SIZE." );

		Binary padded = Bin().reserve( data.size() + BLOCK_SIZE );
		padded.add( data );
		Crypt.pad( padded, BLOCK_SIZE, alignMode );

		MUST( (padded.size() & (BLOCK_SIZE - 1)) == 0, "Wrong data. Must be multiple of BLOCK_SIZE" );

		encryptFirst( Bin(), Bin(), cryptMode, alignMode, iv );
		encryptNext( padded, padded );

		return padded;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные с нулевым начальным вектором.
	 * 
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
	 * 
	 * @param data Массив входных данных (может быть нулевого размера, или кратным [16 байт])
	 * @param crypt Массив для выходных данных (того же размера как и data)
	 * @param cryptMode Режим шифрования
	 * @param alignMode Режим выравнивания
	 * @param iv Начальный вектор
	 */
	public void encryptFirst( final Binary data, Binary crypt, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be BLOCK_SIZE bytes." );

		this.crypt_mode = cryptMode;
		this.align_mode = alignMode;
		this.temp_IV = (cryptMode == CryptoMode.ECB) ? IV0.clone() : iv.clone();

		encryptNext( data, crypt );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные в потоковом режиме: Промежуточные шаги.
	 * 
	 * @param data Массив входных данных (может быть нулевого размера, или кратным [16 байт])
	 * @param crypt Массив для выходных данных ( того же размера как и data )
	 */
	public void encryptNext( final Binary data, Binary crypt )
	{
		MUST( crypt.size() == data.size(), "data and crypt must be equal size" );
		MUST( (data.size() & (BLOCK_SIZE - 1)) == 0, "Wrong data. Must be multiple of BLOCK_SIZE" );

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
	 * 
	 * @param data Массив входных данных (кратный [16 байт] если AlignMode.BLOCK, любого размера
	 * если AlignMode.NONE)
	 * @param crypt Массив для выходных данных (того же размера как и data)</br>
	 * при AlignMode.BLOCK меняется размер crypt.data
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
	 * 
	 * @param crypt Входные зашифрованные данные
	 * @param cryptMode Режим дешифрования
	 * @param alignMode Режим выравнивания
	 * @param iv Входной начальный вектор
	 * @return Расшифрованные данные
	 */
	public Binary decrypt( Binary crypt, CryptoMode cryptMode, AlignMode alignMode, Binary iv )
	{
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be BLOCK_SIZE." );
		MUST( ( crypt.size() & (BLOCK_SIZE - 1) ) == 0, "Wrong data. Must be multiple of BLOCK_SIZE" );

		Binary data = Bin( crypt.size() );
		decryptFirst( Bin(), Bin(), cryptMode, alignMode, iv );
		decryptNext( crypt, data );
		Crypt.unPad( data, BLOCK_SIZE, alignMode );

		return data;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные с нулевым начальным вектором.
	 * 
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
	 * 
	 * @param crypt Массив входных данных (нулевого размера, или кратный [16 байт])
	 * @param data Массив для выходных данных (того же размера как и crypt)
	 * @param cryptMode Режим шифрования
	 * @param alignMode Режим выравнивания
	 * @param iv Начальный вектор
	 */
	public void decryptFirst( final Binary crypt, Binary data, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be BLOCK_SIZE." );

		this.crypt_mode = cryptMode;
		this.align_mode = alignMode;
		this.temp_IV = (cryptMode == CryptoMode.ECB) ? IV0.clone() : iv.clone();

		decryptNext( crypt, data );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные в потоковом режиме: Промежуточные шаги.
	 * 
	 * @param crypt Массив входных данных (нулевого размера, или кратный [16 байт])
	 * @param data Массив для выходных данных (того же размера как и crypt)
	 */
	public void decryptNext( final Binary crypt, Binary data )
	{
		MUST( crypt.size() == data.size(), "crypt and data must be equal size" );
		MUST( (crypt.size() & (BLOCK_SIZE - 1)) == 0, "Wrong data. Must be multiple of BLOCK_SIZE" );

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

			System.arraycopy( temp_block.getDataRef(), 0, data.getDataRef(), i, BLOCK_SIZE );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные в потоковом режиме: Последний шаг.
	 * 
	 * @param crypt Массив входных данных (кратный [16 байт])
	 * @param data Массив для выходных данных (того же размера как и crypt) при AlignMode.BLOCK
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
	 * 
	 * @param data Входные данные
	 * @param alignMode Режим выравнивания
	 * @param ccsMode Режим контрольной суммы
	 * @param iv Начальный вектор
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
	 * 
	 * @param data Входные данные
	 * @param alignMode Режим выравнивания
	 * @param ccsMode Режим контрольной суммы
	 * @return Контрольная сумма
	 */
	public Binary calcCCS( final Binary data, AlignMode alignMode, CCSMode ccsMode )
	{
		return calcCCS( data, alignMode, ccsMode, IV0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить криптографическую контрольную сумму в потоковом режиме: Первый шаг.</br>
	 * Данные должны быть кратны [16 байт].
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
	 * Данные должны быть кратны [16 байт].
	 * @param data Входной массив
	 */
	public void calcCCSnext( final Binary data )
	{
		Binary temp = Bin( data.size() );
		encryptNext( data, temp );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить криптографическую контрольную сумму в потоковом режиме: Последний шаг.</br>
	 * Размер ccs.data становится [16 байт].
	 * 
	 * @param data Входной массив
	 * @param ccs Выходной массив
	 */
	public void calcCCSlast( final Binary data, Binary ccs )
	{
		Binary temp = Bin( data.size() );
		encryptLast( data, temp );

		ccs.assign( temp.slice( temp.size() - BLOCK_SIZE , BLOCK_SIZE ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	// temp_IV - инициализируется через iv; в случае отсутствия iv - через IV0
	private Binary temp_IV = Bin( BLOCK_SIZE );

	// задается в encryptFirst/decryptFirst
	private CryptoMode crypt_mode;
	// задается в encryptFirst/decryptFirst
	private AlignMode align_mode;
	// вынесли из ecnryptNext/decryptNext
	private Binary temp_block = Bin( BLOCK_SIZE );
	// вынесли из decryptNext
	private Binary prev_IV = Bin( BLOCK_SIZE );

	private Binary m_key;

	// -----------------------------------------------------------------------------------------------------------------
	// -----------------------------------------------------------------------------------------------------------------
	private static final Binary IV0 = new Binary( BLOCK_SIZE );

	/**
	 * Substitution table (S-box).
	 */
	private static final byte[] SBOX = {
		(byte)0x63, (byte)0x7C, (byte)0x77, (byte)0x7B, (byte)0xF2, (byte)0x6B, (byte)0x6F, (byte)0xC5,
		(byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2B, (byte)0xFE, (byte)0xD7, (byte)0xAB, (byte)0x76,
		(byte)0xCA, (byte)0x82, (byte)0xC9, (byte)0x7D, (byte)0xFA, (byte)0x59, (byte)0x47, (byte)0xF0,
		(byte)0xAD, (byte)0xD4, (byte)0xA2, (byte)0xAF, (byte)0x9C, (byte)0xA4, (byte)0x72, (byte)0xC0,
		(byte)0xB7, (byte)0xFD, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3F, (byte)0xF7, (byte)0xCC,
		(byte)0x34, (byte)0xA5, (byte)0xE5, (byte)0xF1, (byte)0x71, (byte)0xD8, (byte)0x31, (byte)0x15,
		(byte)0x04, (byte)0xC7, (byte)0x23, (byte)0xC3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9A,
		(byte)0x07, (byte)0x12, (byte)0x80, (byte)0xE2, (byte)0xEB, (byte)0x27, (byte)0xB2, (byte)0x75,
		(byte)0x09, (byte)0x83, (byte)0x2C, (byte)0x1A, (byte)0x1B, (byte)0x6E, (byte)0x5A, (byte)0xA0,
		(byte)0x52, (byte)0x3B, (byte)0xD6, (byte)0xB3, (byte)0x29, (byte)0xE3, (byte)0x2F, (byte)0x84,
		(byte)0x53, (byte)0xD1, (byte)0x00, (byte)0xED, (byte)0x20, (byte)0xFC, (byte)0xB1, (byte)0x5B,
		(byte)0x6A, (byte)0xCB, (byte)0xBE, (byte)0x39, (byte)0x4A, (byte)0x4C, (byte)0x58, (byte)0xCF,
		(byte)0xD0, (byte)0xEF, (byte)0xAA, (byte)0xFB, (byte)0x43, (byte)0x4D, (byte)0x33, (byte)0x85,
		(byte)0x45, (byte)0xF9, (byte)0x02, (byte)0x7F, (byte)0x50, (byte)0x3C, (byte)0x9F, (byte)0xA8,
		(byte)0x51, (byte)0xA3, (byte)0x40, (byte)0x8F, (byte)0x92, (byte)0x9D, (byte)0x38, (byte)0xF5,
		(byte)0xBC, (byte)0xB6, (byte)0xDA, (byte)0x21, (byte)0x10, (byte)0xFF, (byte)0xF3, (byte)0xD2,
		(byte)0xCD, (byte)0x0C, (byte)0x13, (byte)0xEC, (byte)0x5F, (byte)0x97, (byte)0x44, (byte)0x17,
		(byte)0xC4, (byte)0xA7, (byte)0x7E, (byte)0x3D, (byte)0x64, (byte)0x5D, (byte)0x19, (byte)0x73,
		(byte)0x60, (byte)0x81, (byte)0x4F, (byte)0xDC, (byte)0x22, (byte)0x2A, (byte)0x90, (byte)0x88,
		(byte)0x46, (byte)0xEE, (byte)0xB8, (byte)0x14, (byte)0xDE, (byte)0x5E, (byte)0x0B, (byte)0xDB,
		(byte)0xE0, (byte)0x32, (byte)0x3A, (byte)0x0A, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5C,
		(byte)0xC2, (byte)0xD3, (byte)0xAC, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xE4, (byte)0x79,
		(byte)0xE7, (byte)0xC8, (byte)0x37, (byte)0x6D, (byte)0x8D, (byte)0xD5, (byte)0x4E, (byte)0xA9,
		(byte)0x6C, (byte)0x56, (byte)0xF4, (byte)0xEA, (byte)0x65, (byte)0x7A, (byte)0xAE, (byte)0x08,
		(byte)0xBA, (byte)0x78, (byte)0x25, (byte)0x2E, (byte)0x1C, (byte)0xA6, (byte)0xB4, (byte)0xC6,
		(byte)0xE8, (byte)0xDD, (byte)0x74, (byte)0x1F, (byte)0x4B, (byte)0xBD, (byte)0x8B, (byte)0x8A,
		(byte)0x70, (byte)0x3E, (byte)0xB5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xF6, (byte)0x0E,
		(byte)0x61, (byte)0x35, (byte)0x57, (byte)0xB9, (byte)0x86, (byte)0xC1, (byte)0x1D, (byte)0x9E,
		(byte)0xE1, (byte)0xF8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xD9, (byte)0x8E, (byte)0x94,
		(byte)0x9B, (byte)0x1E, (byte)0x87, (byte)0xE9, (byte)0xCE, (byte)0x55, (byte)0x28, (byte)0xDF,
		(byte)0x8C, (byte)0xA1, (byte)0x89, (byte)0x0D, (byte)0xBF, (byte)0xE6, (byte)0x42, (byte)0x68,
		(byte)0x41, (byte)0x99, (byte)0x2D, (byte)0x0F, (byte)0xB0, (byte)0x54, (byte)0xBB, (byte)0x16 };

	private static final byte[] Se = new byte[ 256 ];

	private static final int[] Te0 = new int[ 256 ];
	private static final int[] Te1 = new int[ 256 ];
	private static final int[] Te2 = new int[ 256 ];
	private static final int[] Te3 = new int[ 256 ];

	private static final byte[] Sd = new byte[ 256 ];

	private static final int[] Td0 = new int[ 256 ];
	private static final int[] Td1 = new int[ 256 ];
	private static final int[] Td2 = new int[ 256 ];
	private static final int[] Td3 = new int[ 256 ];

	/**
	 * Round constants for 128-bit blocks, Rijndael never uses more than 10 rcon values
	 */
	private static final int[] rcon = new int[ 10 ];

	/**
	 * Number of rounds (depends on key size).
	 */
	private int Nr;
	private int Nk;
	private int Nw;

	/**
	 * Encryption key schedule
	 */
	private int[] rek;

	/**
	 * Decryption key schedule
	 */
	private int[] rdk;

	// -----------------------------------------------------------------------------------------------------------------
	static {
		int ROOT = 0x11B;

		for( int i1 = 0; i1 < 256; ++i1 )
		{
			int s1 = SBOX[ i1 ] & 0xff;

			int s2 = s1 << 1;
			if( s2 >= 0x100 )
			{
				s2 ^= ROOT;
			}
			int s3 = s2 ^ s1;
			int i2 = i1 << 1;
			if( i2 >= 0x100 )
			{
				i2 ^= ROOT;
			}
			int i4 = i2 << 1;
			if( i4 >= 0x100 )
			{
				i4 ^= ROOT;
			}
			int i8 = i4 << 1;
			if( i8 >= 0x100 )
			{
				i8 ^= ROOT;
			}
			int i9 = i8 ^ i1;
			int ib = i9 ^ i2;
			int id = i9 ^ i4;
			int ie = i8 ^ i4 ^ i2;

			Se[ i1 ] = (byte)s1;
			int t = (s2 << 24) | (s1 << 16) | (s1 << 8) | s3;
			Te0[ i1 ] = t ;
			Te1[ i1 ] = (t >>>  8) | (t << 24);
			Te2[ i1 ] = (t >>> 16) | (t << 16);
			Te3[ i1 ] = (t >>> 24) | (t << 8);

			Sd[ s1 ] = (byte)i1;
			t = (ie << 24) | (i9 << 16) | (id << 8) | ib;
			Td0[ s1 ] = t;
			Td1[ s1 ] = (t >>>  8) | (t << 24);
			Td2[ s1 ] = (t >>> 16) | (t << 16);
			Td3[ s1 ] = (t >>> 24) | (t << 8);
		}

		// round constants
		int r = 1;
		rcon[ 0 ] = r << 24;
		for( int i = 1; i < 10; i++ )
		{
			r <<= 1;
			if( r >= 0x100 )
			{
				r ^= ROOT;
			}
			rcon[ i ] = r << 24;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void expandKey( Binary cipherKey )
	{
		int temp = 0;
		
		int k = 0;
		for( int i = 0; i < Nk; ++i )
		{
			rek[ i ] = cipherKey.getIntBE( k );
			k += 4;
		}

		int r = 0;
		int n = 0;
		for( int i = Nk; i < Nw; ++i )
		{
			temp = rek[ i - 1 ];
			if( n == 0 )
			{
				n = Nk;
				temp =
					((Se[ (temp >>> 16) & 0xff ]       ) << 24) |
					((Se[ (temp >>>  8) & 0xff ] & 0xff) << 16) |
					((Se[ (temp       ) & 0xff ] & 0xff) <<  8) |
					((Se[ (temp >>> 24)        ] & 0xff));
				temp ^= rcon[ r++ ];
			}
			else if( (Nk == 8) && (n == 4) )
			{
				temp =
					((Se[ (temp >>> 24)        ]       ) << 24) |
					((Se[ (temp >>> 16) & 0xff ] & 0xff) << 16) |
					((Se[ (temp >>>  8) & 0xff ] & 0xff) <<  8) |
					((Se[ (temp       ) & 0xff ] & 0xff));
			}
			rek[ i ] = rek[ i - Nk ] ^ temp;
			--n;
		}
		temp = 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Compute the decryption schedule from the encryption schedule .
	 */
	private void invertKey()
	{
		int d = 0;
		int e = 4 * Nr;

		rdk[ d ] = rek[ e ];
		rdk[ d + 1 ] = rek[ e + 1 ];
		rdk[ d + 2 ] = rek[ e + 2 ];
		rdk[ d + 3 ] = rek[ e + 3 ];
		d += 4;
		e -= 4;
		for( int r = 1; r < Nr; ++r )
		{
			for( int n = 0; n < 4; ++n )
			{
				int w = rek[ e + n ];
				rdk[ d + n ] =
					Td0[ Se[ (w >>> 24)        ] & 0xff] ^
					Td1[ Se[ (w >>> 16) & 0xff ] & 0xff] ^
					Td2[ Se[ (w >>>  8) & 0xff ] & 0xff] ^
					Td3[ Se[ (w       ) & 0xff ] & 0xff];
			}
			d += 4;
			e -= 4;
		}
		rdk[ d ] = rek[ e ];
		rdk[ d + 1 ] = rek[ e + 1 ];
		rdk[ d + 2 ] = rek[ e + 2 ];
		rdk[ d + 3 ] = rek[ e + 3 ];
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать блок ({@link #BLOCK_SIZE} байт) данных.
	 * @param block блок данных
	 */
	public void encryptBlock( Binary block )
	{
		MUST( block.size() == BLOCK_SIZE, "Incorrect block size" );

		int t0 = block.getIntBE( 0 ) ^ rek[ 0 ];
		int t1 = block.getIntBE( 4 ) ^ rek[ 1 ];
		int t2 = block.getIntBE( 8 ) ^ rek[ 2 ];
		int t3 = block.getIntBE( 12 ) ^ rek[ 3 ];

		int k = 0;
		for( int r = 1; r < Nr; ++r )
		{
			k += 4;
			int a0 =
				Te0[ (t0 >>> 24)        ] ^
				Te1[ (t1 >>> 16) & 0xff ] ^
				Te2[ (t2 >>>  8) & 0xff ] ^
				Te3[ (t3       ) & 0xff ] ^
				rek[ k ];
			int a1 =
				Te0[ (t1 >>> 24)        ] ^
				Te1[ (t2 >>> 16) & 0xff ] ^
				Te2[ (t3 >>>  8) & 0xff ] ^
				Te3[ (t0       ) & 0xff ] ^
				rek[ k + 1 ];
			int a2 =
				Te0[ (t2 >>> 24)        ] ^
				Te1[ (t3 >>> 16) & 0xff ] ^
				Te2[ (t0 >>>  8) & 0xff ] ^
				Te3[ (t1       ) & 0xff ] ^
				rek[ k + 2 ];
			int a3 =
				Te0[ (t3 >>> 24)        ] ^
				Te1[ (t0 >>> 16) & 0xff ] ^
				Te2[ (t1 >>>  8) & 0xff ] ^
				Te3[ (t2       ) & 0xff ] ^
				rek[ k + 3 ];
			t0 = a0;
			t1 = a1;
			t2 = a2;
			t3 = a3;
		}

		k += 4;

		int v = rek[ k ];
		byte[] block_arr = block.getDataRef();
		block_arr[ 0 ] = (byte)(Se[ (t0 >>> 24)        ] ^ (v >>> 24));
		block_arr[ 1 ] = (byte)(Se[ (t1 >>> 16) & 0xff ] ^ (v >>> 16));
		block_arr[ 2 ] = (byte)(Se[ (t2 >>>  8) & 0xff ] ^ (v >>>  8));
		block_arr[ 3 ] = (byte)(Se[ (t3       ) & 0xff ] ^ (v));

		v = rek[ k + 1 ];
		block_arr[ 4 ] = (byte)(Se[ (t1 >>> 24)       ] ^ (v >>> 24));
		block_arr[ 5 ] = (byte)(Se[ (t2 >>> 16) & 0xff] ^ (v >>> 16));
		block_arr[ 6 ] = (byte)(Se[ (t3 >>>  8) & 0xff] ^ (v >>>  8));
		block_arr[ 7 ] = (byte)(Se[ (t0       ) & 0xff] ^ (v));

		v = rek[ k + 2 ];
		block_arr[  8 ] = (byte)(Se[ (t2 >>> 24)        ] ^ (v >>> 24));
		block_arr[  9 ] = (byte)(Se[ (t3 >>> 16) & 0xff ] ^ (v >>> 16));
		block_arr[ 10 ] = (byte)(Se[ (t0 >>>  8) & 0xff ] ^ (v >>>  8));
		block_arr[ 11 ] = (byte)(Se[ (t1       ) & 0xff ] ^ (v));

		v = rek[ k + 3 ];
		block_arr[ 12 ] = (byte)(Se[ (t3 >>> 24)        ] ^ (v >>> 24));
		block_arr[ 13 ] = (byte)(Se[ (t0 >>> 16) & 0xff ] ^ (v >>> 16));
		block_arr[ 14 ] = (byte)(Se[ (t1 >>>  8) & 0xff ] ^ (v >>>  8));
		block_arr[ 15 ] = (byte)(Se[ (t2       ) & 0xff ] ^ (v));
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать блок ({@link #BLOCK_SIZE} байт) зашифрованных данных.
	 * @param block блок данных
	 */
	public void decryptBlock( Binary block )
	{
		MUST( block.size() == BLOCK_SIZE, "Incorrect block size" );

		int t0 = block.getIntBE(  0 ) ^ rdk[ 0 ];
		int t1 = block.getIntBE(  4 ) ^ rdk[ 1 ];
		int t2 = block.getIntBE(  8 ) ^ rdk[ 2 ];
		int t3 = block.getIntBE( 12 ) ^ rdk[ 3 ];

		int k = 0;
		for( int r = 1; r < Nr; ++r )
		{
			k += 4;
			int a0 =
				Td0[ (t0 >>> 24)        ] ^
				Td1[ (t3 >>> 16) & 0xff ] ^
				Td2[ (t2 >>>  8) & 0xff ] ^
				Td3[ (t1       ) & 0xff ] ^
				rdk[ k ];
			int a1 =
				Td0[ (t1 >>> 24)        ] ^
				Td1[ (t0 >>> 16) & 0xff ] ^
				Td2[ (t3 >>>  8) & 0xff ] ^
				Td3[ (t2       ) & 0xff ] ^
				rdk[ k + 1 ];
			int a2 =
				Td0[ (t2 >>> 24)        ] ^
				Td1[ (t1 >>> 16) & 0xff ] ^
				Td2[ (t0 >>>  8) & 0xff ] ^
				Td3[ (t3       ) & 0xff ] ^
				rdk[ k + 2 ];
			int a3 =
				Td0[ (t3 >>> 24)        ] ^
				Td1[ (t2 >>> 16) & 0xff ] ^
				Td2[ (t1 >>>  8) & 0xff ] ^
				Td3[ (t0       ) & 0xff ] ^
				rdk[ k + 3 ];
			t0 = a0;
			t1 = a1;
			t2 = a2;
			t3 = a3;
		}

		k += 4;

		int v = rdk[ k ];
		byte[] block_arr = block.getDataRef();
		block_arr[ 0 ] = (byte)(Sd[ (t0 >>> 24)        ] ^ (v >>> 24));
		block_arr[ 1 ] = (byte)(Sd[ (t3 >>> 16) & 0xff ] ^ (v >>> 16));
		block_arr[ 2 ] = (byte)(Sd[ (t2 >>>  8) & 0xff ] ^ (v >>> 8));
		block_arr[ 3 ] = (byte)(Sd[ (t1       ) & 0xff ] ^ (v));

		v = rdk[ k + 1 ];
		block_arr[ 4 ] = (byte)(Sd[ (t1 >>> 24)        ] ^ (v >>> 24));
		block_arr[ 5 ] = (byte)(Sd[ (t0 >>> 16) & 0xff ] ^ (v >>> 16));
		block_arr[ 6 ] = (byte)(Sd[ (t3 >>>  8) & 0xff ] ^ (v >>> 8));
		block_arr[ 7 ] = (byte)(Sd[ (t2       ) & 0xff ] ^ (v));

		v = rdk[ k + 2 ];
		block_arr[  8 ] = (byte)(Sd[ (t2 >>> 24)        ] ^ (v >>> 24));
		block_arr[  9 ] = (byte)(Sd[ (t1 >>> 16) & 0xff ] ^ (v >>> 16));
		block_arr[ 10 ] = (byte)(Sd[ (t0 >>>  8) & 0xff ] ^ (v >>> 8));
		block_arr[ 11 ] = (byte)(Sd[ (t3       ) & 0xff ] ^ (v));

		v = rdk[ k + 3 ];
		block_arr[ 12 ] = (byte)(Sd[ (t3 >>> 24)        ] ^ (v >>> 24));
		block_arr[ 13 ] = (byte)(Sd[ (t2 >>> 16) & 0xff ] ^ (v >>> 16));
		block_arr[ 14 ] = (byte)(Sd[ (t1 >>>  8) & 0xff ] ^ (v >>> 8));
		block_arr[ 15 ] = (byte)(Sd[ (t0       ) & 0xff ] ^ (v));
	}

}
