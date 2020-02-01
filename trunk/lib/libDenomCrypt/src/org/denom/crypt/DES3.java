// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.crypt;

import org.denom.*;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

/**
 * Шифр TripleDES (DES-EDE2).
 */
public class DES3
{
	public static final int KEY_SIZE = 16;
	public static final int BLOCK_SIZE = 8;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Ключ задать позже.
	 */
	public DES3()
	{
		this( Bin(KEY_SIZE) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param key Ключ [16 байт]
	 */
	public DES3( final Binary key )
	{
		des1 = new DES( new Binary( BLOCK_SIZE ) );
		des2 = new DES( new Binary( BLOCK_SIZE ) );
		setKey( key );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать ключ шифрования.
	 * @param key Ключ [16 байт]
	 */
	public DES3 setKey( final Binary key )
	{
		MUST( key.size() == KEY_SIZE, "Wrong key size" );
		des1.setKey( key, 0 );
		des2.setKey( key, DES.KEY_SIZE );
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
		return Bin( des1.getKey(), des2.getKey() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сгенерировать случайный ключ. Ключ будет установлен в качестве текущего.
	 */
	public Binary generateKey()
	{
		des1.generateKey();
		des2.generateKey();
		return getKey();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные.
	 * @param data Входные данные
	 * @param cryptMode Режим шифрования
	 * @param alignMode Режим выравнивания
	 * @param iv Входной начальный вектор
	 * @return Зашифрованные данные
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
	 * @param data Массив входных данных (нулевого размера, или кратный [8 байт])
	 * @param crypt Массив для выходных данных (того же размера как и data)
	 * @param cryptMode Режим шифрования
	 * @param alignMode Режим выравнивания
	 * @param iv Начальный вектор
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
	 * @param data Массив входных данных (нулевого размера, или кратный [8 байт])
	 * @param crypt Массив для выходных данных (того же размера как и data)
	 */
	public void encryptNext( final Binary data, Binary crypt)
	{
		MUST( crypt.size() == data.size(), "data and crypt must be equal size" );
		MUST( (data.size() & (BLOCK_SIZE - 1)) == 0, "Wrong data. Must be multiple of 8 bytes" );

		for( int i = 0; i < data.size(); i += BLOCK_SIZE )
		{
			temp_block.assign( data, i, BLOCK_SIZE );

			switch( crypt_mode )
			{
				case ECB:
					des1.encryptBlock( temp_block );
					des2.decryptBlock( temp_block );
					des1.encryptBlock( temp_block );
					break;

				case CBC:
					temp_block.xor( temp_IV );

					des1.encryptBlock( temp_block );
					des2.decryptBlock( temp_block );
					des1.encryptBlock( temp_block );

					temp_IV.assign( temp_block );
					break;

				case CFB:
					des1.encryptBlock( temp_IV );
					des2.decryptBlock( temp_IV );
					des1.encryptBlock( temp_IV );

					temp_block.xor( temp_IV );
					temp_IV.assign( temp_block );
					break;

				case OFB:
					des1.encryptBlock( temp_IV );
					des2.decryptBlock( temp_IV );
					des1.encryptBlock( temp_IV );

					temp_block.xor( temp_IV );
					break;
			}

			System.arraycopy( temp_block.getDataRef(), 0, crypt.getDataRef(), i, 8 );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные в потоковом режиме: Последний шаг.
	 * @param data - Массив входных данных (кратный [8 байт] если AlignMode.BLOCK, любого размера если
	 * AlignMode.NONE)
	 * @param crypt - Массив для выходных данных (того же размера как и data),</br>
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
	 * @param crypt - Входные зашифрованные данные
	 * @param cryptMode - Режим дешифрования
	 * @param alignMode - Режим выравнивания
	 * @param iv - Входной начальный вектор
	 * @return Расшифрованные данные
	 */
	public Binary decrypt( final Binary crypt, CryptoMode cryptMode, AlignMode alignMode, final Binary iv )
	{
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be 8 bytes." );
		MUST( (crypt.size() & (BLOCK_SIZE - 1)) == 0, "Wrong data. Must be multiple of 8 bytes" );

		Binary data = Bin( crypt.size() );
		decryptFirst( Bin(), Bin(), cryptMode, alignMode, iv );
		decryptNext( crypt, data );
		Crypt.unPad( data, BLOCK_SIZE, alignMode );

		return data;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные с нулевым начальным вектором.
	 * @param crypt - Входные зашифрованные данные
	 * @param cryptMode - Режим дешифрования
	 * @param alignMode - Режим выравнивания
	 * @return Расшифрованные данные
	 */
	public Binary decrypt( final Binary crypt, CryptoMode cryptMode, AlignMode alignMode )
	{
		return decrypt( crypt, cryptMode, alignMode, IV0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные в потоковом режиме: Первый шаг.
	 * @param crypt - Массив входных данных (нулевого размера, или кратный [8 байт])
	 * @param data - Массив для выходных данных (того же размера как и crypt)
	 * @param cryptMode - Режим шифрования
	 * @param alignMode - Режим выравнивания
	 * @param iv - Начальный вектор
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
	 * 
	 * @param crypt Массив входных данных (нулевого размера, или кратный [8 байт])
	 * @param data Массив для выходных данных (того же размера как и crypt)
	 */
	public void decryptNext( final Binary crypt, Binary data )
	{
		MUST( crypt.size() == data.size(), "crypt and data must be equal size" );
		MUST( (crypt.size() & (BLOCK_SIZE - 1) ) == 0, "Wrong data. Must be multiple of 8 bytes" );

		for( int i = 0; i < crypt.size(); i += 8 )
		{
			temp_block.assign( crypt, i, 8 );

			switch( crypt_mode )
			{
				case ECB:
					des1.decryptBlock( temp_block );
					des2.encryptBlock( temp_block );
					des1.decryptBlock( temp_block );
					break;

				case CBC:
					prev_IV.assign( temp_block );

					des1.decryptBlock( temp_block );
					des2.encryptBlock( temp_block );
					des1.decryptBlock( temp_block );

					temp_block.xor( temp_IV );
					temp_IV.assign( prev_IV );
					break;

				case CFB:
					prev_IV.assign( temp_block );

					des1.encryptBlock( temp_IV );
					des2.decryptBlock( temp_IV );
					des1.encryptBlock( temp_IV );

					temp_block.xor( temp_IV );
					temp_IV.assign( prev_IV );
					break;

				case OFB:
					des1.encryptBlock( temp_IV );
					des2.decryptBlock( temp_IV );
					des1.encryptBlock( temp_IV );

					temp_block.xor( temp_IV );
					break;
			}

			System.arraycopy( temp_block.getDataRef(), 0, data.getDataRef(), i, 8 );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные в потоковом режиме: Последний шаг.
	 * 
	 * @param crypt Массив входных данных (кратный [8 байт])
	 * @param data Массив для выходных данных (того же размера как и crypt) при AlignMode.BLOCK
	 * меняет размер data.data
	 */
	public void decryptLast( final Binary crypt, Binary data )
	{
		if( align_mode == AlignMode.BLOCK)
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
		//MUST( !data.empty(), "No data" );
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be 8 bytes." );

		Binary ccs = Bin();
		calcCCSfirst( Bin(), alignMode, ccsMode, iv );
		calcCCSlast( data, ccs );

		return ccs;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить криптографическую контрольную сумму с нулевым начальным вектором.
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
	 * Данные должны быть кратны [8 байт].
	 * @param data Входной массив
	 * @param alignMode Режим выравнивания
	 * @param ccsMode Режим контрольной суммы
	 * @param iv Начальный вектор
	 */
	public void calcCCSfirst( final Binary data, AlignMode alignMode, CCSMode ccsMode, final Binary iv )
	{
		switch( ccsMode )
		{
			case CLASSIC:
				Binary temp = Bin( data.size() );
				encryptFirst( data, temp, CryptoMode.CBC, AlignMode.NONE, iv );

				break;
			case FAST:
				des1.calcCCSfirst( data, alignMode, CCSMode.FAST, iv );
				this.ccsFast_IV = iv.clone();

				break;
		}
		this.ccs_mode = ccsMode;
		this.align_mode = alignMode;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить криптографическую контрольную сумму в потоковом режиме: Промежуточные шаги.</br>
	 * Данные должны быть кратны [8 байт].
	 * @param data Входной массив
	 */
	public void calcCCSnext( final Binary data )
	{
		switch( ccs_mode )
		{
			case CLASSIC:
				Binary temp = Bin( data.size() );
				encryptNext( data, temp );
				break;
			case FAST:
				des1.calcCCSnext( data );
				break;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить криптографическую контрольную сумму в потоковом режиме: Последний шаг.</br>
	 * Размер ccs становится [8 байт].
	 * @param data Входной массив
	 */
	public void calcCCSlast( final Binary data, Binary ccs )
	{
		Binary out = Bin( data.size() );
		switch( ccs_mode )
		{
			case CLASSIC:
				encryptLast( data, out );
				ccs.assign( out, out.size() - BLOCK_SIZE, BLOCK_SIZE );

				break;
			case FAST:
				ccs.assign( out );
				des1.calcCCSlast( data, ccs );

				des2.decryptFirst( Bin(), Bin(), CryptoMode.ECB, AlignMode.NONE, ccsFast_IV );
				des2.decryptLast( ccs, ccs );

				des1.encryptFirst( Bin(), Bin(), CryptoMode.ECB, AlignMode.NONE, ccsFast_IV );
				des1.encryptLast( ccs, ccs );
				break;
		}
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить контрольное значение для ключа.
	 * @param keyValue тело ключа [16 байт].
	 * @return контрольное значение [3 байта].
	 */
	public static Binary calcKCV( final Binary keyValue )
	{
		Binary crypt = new DES3( keyValue ).encrypt( Bin( 8 ), CryptoMode.ECB, AlignMode.NONE );
		return crypt.slice( 0, 3 );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	private DES des1;
	private DES des2;

	private CCSMode ccs_mode;
	private Binary ccsFast_IV;

	private Binary temp_IV = Bin( BLOCK_SIZE );
	private CryptoMode crypt_mode;
	private AlignMode align_mode;

	private Binary temp_block = Bin( BLOCK_SIZE );
	private Binary prev_IV = Bin( BLOCK_SIZE );

	// temp_IV - инициализируется через iv; в случае отсутствия iv - через IV0
	private static final Binary IV0 = new Binary( BLOCK_SIZE );
}
