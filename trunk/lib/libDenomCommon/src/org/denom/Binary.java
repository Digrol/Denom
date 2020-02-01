// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom;

import java.io.*;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.Map;

import static org.denom.Ex.*;

/**
 * Байтовый массив переменного размера.<br>
 * Конвертирование из HEX-строк и обратно. Конвертирование в число.
 * Конкатенация и добавление данных в массив. Сравнение на равенство.<br>
 * Если нужен byte[] (для оптимизаций), то можно использовать метод {@link #getDataRef()},
 * он возвращает ссылку на внутренный массив; можно создать массив-копию - {@link #getBytes()}.
 */
public final class Binary implements Comparable<Binary>
{
	/**
	 * Массив байтов, его размер >= size()
	 */
	private byte[] mData;

	/**
	 * Фактический размер данных
	 */
	private int mSize;

	private Random rand;
	private SecureRandom randSecure;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать Binary нулевого размера.
	 */
	public Binary()
	{
		this( 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать Binary, заполненный нулями.
	 * @param size - Размер массива
	 */
	public Binary( int size )
	{
		this( size, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать Binary размером {@code size}, заполненный значениями {@code value}.
	 * @param size - Размер массива
	 * @param value - Байт-заполнитель (учитывается только младший байт)
	 */
	public Binary( int size, int value )
	{
		mData = new byte[ size ];
		mSize = size;
		if( value != 0 )
		{
			Arrays.fill( mData, (byte)(value & 0xFF) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать Binary из HEX-строки.
	 * @param hexStr - HEX-строка
	 */
	public Binary( String hexStr )
	{
		mData = new byte[ hexStr.length() >> 1 ];
		mSize = 0;
		this.add( hexStr );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать Binary из массива байт.
	 * @param data - Массив байт
	 */
	public Binary( byte[] data )
	{
		mData = data.clone();
		mSize = data.length;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать Binary из другого Binary.
	 * @param bin - Массив байт
	 */
	public Binary( Binary bin )
	{
		mData = Arrays.copyOf( bin.mData, bin.size() );
		mSize = mData.length;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать Binary из части массива байт {@code bin}.
	 * @param bin - Массив байт
	 * @param offset - Начало части
	 * @param count - Размер части
	 */
	public Binary( byte[] bin, int offset, int count )
	{
		MUST( (offset >= 0) && (count >= 0) && ((offset + count) <= bin.length), "Out of borders" );
		mData = Arrays.copyOfRange( bin, offset, offset + count );
		mSize = mData.length;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить ссылку на внутренний массив.<br>
	 * Предназначено для оптимизаций, чтобы избежать копирования в getBytes().<br>
	 * Внимание! getDataRef().length >= {@link #size()}.
	 */
	public byte[] getDataRef()
	{
		return mData;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать байтовый массив - копию Binary.
	 */
	public byte[] getBytes()
	{
		return Arrays.copyOf( mData, mSize );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Скопировать часть содержимого Binary в байтовый массив.
	 * @param offset - начало части данных в Binary. 
	 * @param length - размер части.
	 * @param dest - целевой массив.
	 * @param destOffset - смещение в целевом массиве, начиная с которого будут лежать данные.
	 */
	public void getBytes( int offset, int length, byte[] dest, int destOffset )
	{
		MUST( (offset >= 0) && (offset + length <= mSize), "Некорректный диапазон для Binary" );
		MUST( (destOffset >= 0) && (destOffset + length <= dest.length), "Байтовый массив меньше требуемого" );
		System.arraycopy( mData, offset, dest, destOffset, length );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Скопировать всё содержимое Binary в байтовый массив.
	 * @param dest - целевой массив.
	 * @param destOffset - смещение в целевом массиве, начиная с которого будут лежать данные.
	 */
	public void getBytes( byte[] dest, int destOffset )
	{
		MUST( (destOffset >= 0) && (destOffset + mSize <= dest.length), "Байтовый массив меньше требуемого" );
		System.arraycopy( mData, 0, dest, destOffset, mSize );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить размер массива.
	 */
	public int size()
	{
		return mSize;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Преобразовать Binary в HEX-строку.<br>
	 * Аналогично использованию {@code Hex( 1, 0, 0, 0 )}.
	 */
	@Override
	public String toString()
	{
		return Hex( 1, 0, 0, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает true, eсли размер массива равен нулю.
	 */
	public boolean empty()
	{
		return mSize == 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Очистить массив.<br>
	 * Размер массива будет равен 0; выделенная ранее память - НЕ освободится.<br>
	 * Более короткая и наглядная запись, вместо resize(0).
	 */
	public void clear()
	{
		mSize = 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Очистить массив.<br>
	 * Размер массива будет равен 0; память освободится.
	 */
	public void clearMem()
	{
		mData = new byte[ 0 ];
		mSize = 0;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать копию Binary.
	 */
	@Override
	public Binary clone()
	{
		return new Binary( mData, 0, mSize );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static final char[] HEX_DIGITS = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Преобразовать Binary в HEX-строку без пробелов и другого форматирования.
	 */
	public String Hex()
	{
		int size = mSize;
		if( size == 0 )
			return "";

		final char[] out = new char[ size << 1 ];

		int j = 0;
		for( int i = 0; i < size; i++ )
		{
			byte b = mData[ i ];
			out[ j++ ] = HEX_DIGITS[ (0xF0 & b) >>> 4 ];
			out[ j++ ] = HEX_DIGITS[ b & 0x0F ];
		}
		return new String( out );

	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Преобразовать Binary в HEX-строку с форматированием.
	 * @param oneSpace - Через столько байт ставится пробел.
	 */
	public String Hex( int oneSpace )
	{
		return Hex( oneSpace, 0, 0, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Преобразовать Binary в HEX-строку с форматированием.
	 * @param oneSpace - Через столько байт ставится пробел.
	 * @param twoSpaces - Через столько байт ставится 2 пробела.
	 * @param newLine - Через столько байт ставится символ перевода строки.
	 * @param lineShift -  Каждая строка смещается вправо на столько пробелов
	 */
	public String Hex( int oneSpace, int twoSpaces, int newLine, int lineShift )
	{
		int size = mSize;
		if( size == 0 )
			return "";

		// Определим максимальный размер строки символов
		int strlen = size << 1;
		strlen += oneSpace > 0 ? (size / oneSpace) : 0;
		strlen += twoSpaces > 0 ? (size * 2 / twoSpaces) : 0;
		strlen += newLine > 0 ? (size / newLine) : 0;
		strlen += lineShift;
		strlen += newLine > 0 ? (size / newLine) * lineShift : 0;
		final char[] out = new char[ strlen ];

		int j = 0;

		for( int l = 0; l < lineShift; ++l )
		{
			out[ j++ ] = ' ';
		}

		byte b = mData[ 0 ];
		out[ j++ ] = HEX_DIGITS[ (0xF0 & b) >>> 4 ];
		out[ j++ ] = HEX_DIGITS[ b & 0x0F ];

		int s1 = 1;
		int s2 = 1;
		int newl = 1;

		for( int i = 1; i < size; i++ )
		{
			if( newLine == newl )
			{
				out[ j++ ] = '\n';
				for( int l = 0; l < lineShift; ++l )
				{
					out[ j++ ] = ' ';
				}
				newl = 0;
				s2 = 0;
				s1 = 0;
			}
			else if( twoSpaces == s2 )
			{
				out[ j++ ] = ' ';
				out[ j++ ] = ' ';
				s2 = 0;
				s1 = 0;
			}
			else if( oneSpace == s1 )
			{
				out[ j++ ] = ' ';
				s1 = 0;
			}

			b = mData[ i ];
			out[ j++ ] = HEX_DIGITS[ (0xF0 & b) >>> 4 ];
			out[ j++ ] = HEX_DIGITS[ b & 0x0F ];
			s1++;
			s2++;
			newl++;
		}
		return (j == strlen) ? new String( out ) : new String( out, 0, j );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Заполнить Binary данными из массива {@code other}.<br>
	 * Размер массива будет равен {@code length}.
	 * @param other - Массив, из которого будут скопированы данные
	 * @param offset - Смещение в {@code other}
	 * @param length - Количество байт из {@code other}
	 */
	public void assign( final byte[] other, int offset, int length )
	{
		if( mData.length >= length )
		{
			System.arraycopy( other, offset, mData, 0, length );
		}
		else
		{
			mData = Arrays.copyOfRange( other, offset, offset + length );
		}
		mSize = length;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Заполнить Binary данными из массива {@code other}.<br>
	 * Размер массива будет равен {@code other.size()}.
	 * @param other - Массив, из которого будут скопированы данные
	 * @param offset - Смещение в {@code other}
	 * @param length - Количество байт из {@code other}
	 */
	public void assign( final Binary other, int offset, int length )
	{
		assign( other.mData, offset, length );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Заполнить Binary данными из массива {@code other}.<br>
	 * Размер массива будет равен {@code other.length}.
	 * @param other - Массив, из которого будут скопированы данные
	 */
	public void assign( final byte[] other )
	{
		assign( other, 0, other.length );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Заполнить Binary данными из массива {@code other}.<br>
	 * Размер массива будет равен {@code other.size()}.
	 * @param other - Массив байт, из которого будут скопированы данные
	 */
	public void assign( final Binary other )
	{
		assign( other.mData, 0, other.size() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void assign( String otherHex )
	{
		mSize = 0;
		this.add( otherHex );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выделить новый буфер нового размера (если недостаточно места в текущем буфере),
	 * скопировать старые данные в новый буфер.
	 */
	private void ensureCapacity( int newSize )
	{
		if( newSize > mData.length )
		{
			byte[] newData = new byte[ newSize ];
			System.arraycopy( mData, 0, newData, 0, mSize );
			mData = newData;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void ensureCapacityOptimal( int newSize )
	{
		if( newSize > mData.length )
		{
			ensureCapacity( Math.max( newSize, mData.length + (mData.length >>> 1) + 2 ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить в конец один байт.
	 * @param b - Число (учитывается только младший байт)
	 * @return Cсылка на себя
	 */
	public Binary add( int b )
	{
		ensureCapacityOptimal( mSize + 1 );
		mData[ mSize ] = (byte)(b & 0xFF);
		++mSize;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить в конец массива U16, 2-х-байтовое число в BigEndian.
	 * Учитываются только 2 младших байта, старшие игнорируются.
	 * @param i - Число.
	 * @return Cсылка на себя.
	 */
	public Binary addU16( int i )
	{
		ensureCapacityOptimal( mSize + 2 );
		mData[ mSize++ ] = (byte)(i >>> 8);
		mData[ mSize++ ] = (byte)(i & 0xFF);
		return this;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить в конец массива int (4 байта) в формате BigEndian.
	 * @param i - Число.
	 * @return Cсылка на себя
	 */
	public Binary addInt( int i )
	{
		int offset = mSize;
		ensureCapacityOptimal( mSize + 4 );

		mData[ offset++ ] = (byte)(i >>> 24);
		mData[ offset++ ] = (byte)(i >>> 16);
		mData[ offset++ ] = (byte)(i >>>  8);
		mData[ offset   ] = (byte)(i & 0xFF);
		mSize += 4;

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить в конец массива long (8 байт) в формате BigEndian.
	 * @param l - Число.
	 * @return Cсылка на себя.
	 */
	public Binary addLong( long l )
	{
		int offset = mSize;
		ensureCapacityOptimal( mSize + 8 );

		int i1 = (int)(l >>> 32);
		int i2 = (int)(l & 0xFFFFFFFF);

		mData[ offset++ ] = (byte)(i1 >>> 24);
		mData[ offset++ ] = (byte)(i1 >>> 16);
		mData[ offset++ ] = (byte)(i1 >>>  8);
		mData[ offset++ ] = (byte)(i1 & 0xFF);
		mData[ offset++ ] = (byte)(i2 >>> 24);
		mData[ offset++ ] = (byte)(i2 >>> 16);
		mData[ offset++ ] = (byte)(i2 >>>  8);
		mData[ offset   ] = (byte)(i2 & 0xFF);
		mSize += 8;

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Записать в массив long по смещению offset в LittleEndian.
	 * @param l - Число.
	 */
	public Binary addLongLE( long l )
	{
		int offset = mSize;
		ensureCapacityOptimal( mSize + 8 );

		int hi = (int)(l >>> 32);
		int lo = (int)(l & 0xFFFFFFFF);

		mData[ offset     ] = (byte)(lo & 0xFF);
		mData[ offset + 1 ] = (byte)(lo >>>  8);
		mData[ offset + 2 ] = (byte)(lo >>> 16);
		mData[ offset + 3 ] = (byte)(lo >>> 24);
		offset += 4;
		mData[ offset     ] = (byte)(hi & 0xFF);
		mData[ offset + 1 ] = (byte)(hi >>>  8);
		mData[ offset + 2 ] = (byte)(hi >>> 16);
		mData[ offset + 3 ] = (byte)(hi >>> 24);
		mSize += 8;

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить в конец часть массива байт {@code data}. 
	 * @param data - Массив байт
	 * @param offset - Смещение начала части
	 * @param len - Количество байт для добавления
	 * @return Ссылка на себя
	 */
	public Binary add( byte[] data, int offset, int len )
	{
		ensureCapacityOptimal( mSize + len );
		System.arraycopy( data, offset, mData, mSize, len );
		mSize += len;
		return this;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить в конец массив байт.
	 * @param data - Массив байт
	 * @return Ссылка на себя
	 */
	public Binary add( byte[] data )
	{
		return add( data, 0, data.length );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить в конец Binary.
	 * @param right - Массив байт.
	 * @return Ссылка на себя.
	 */
	public Binary add( Binary right )
	{
		return add( right.mData, 0, right.size() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить в конец этого массива несколько других Binary.
	 * @param right - Массив байт.
	 * @return Ссылка на себя.
	 */
	public Binary add( Binary... bins )
	{
		for( Binary b : bins )
			this.add( b );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить в конец HEX-строку.
	 * @param hexStr - HEX-строка
	 * @return Ссылка на себя
	 */
	public Binary add( String hexStr )
	{
		char[] chars = hexStr.toCharArray();
		int charsLen = chars.length;

		ensureCapacity( mSize + (charsLen >> 1) );

		int nibble = 0; // Текущий nibble
		int highNibble = 0; // Старший nibble
		boolean flag = false; // Установлен, если найден старший нибл очередного байта
		byte[] data = mData;

		for( int i = 0; i < charsLen; ++i )
		{
			char ch = chars[ i ];
			if( (ch == ' ') || (ch == '\t') || (ch == '\n') || (ch == '\r') )
			{
				continue;
			}
			
			if( (ch >= '0') && (ch <= '9') )
			{
				nibble = ch - '0';
			}
			else if( (ch >= 'A') && (ch <= 'F') )
			{
				nibble = ch - 'A' + 10;
			}
			else if( (ch >= 'a') && (ch <= 'f') )
			{
				nibble = ch - 'a' + 10;
			}
			else
			{
				THROW( "Wrong symbol in HEX-string" );
			}

			if( flag )
			{
				data[ mSize++ ] = (byte)(highNibble | nibble);
				flag = false; // Записали байт в массив
			}
			else
			{
				highNibble = nibble << 4;
				flag = true;
			}
		}
		MUST( !flag, "Odd number of HEX digits in HEX-string" );

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Заполнить часть Binary указанным байтом.
	 * @param b - Байт-заполнитель (учитывается только младший байт).
	 * @param offset - начало диапазона.
	 * @param len - длина диапазона.
	 */
	public void fill( int b, int offset, int len )
	{
		MUST( (offset + len) <= mSize, "Выход за границы Binary" );
		Arrays.fill( mData, offset, offset + len, (byte)(b & 0xFF) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Заполнить весь Binary указанным байтом.
	 * @param b - Байт-заполнитель (учитывается только младший байт).
	 */
	public void fill( int b )
	{
		Arrays.fill( mData, 0, mSize, (byte)(b & 0xFF) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public boolean equals( Object obj )
	{
		if( obj instanceof Binary )
		{
			return equals( (Binary)obj );
		}
		return false;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сравнить с другим Binary.
	 * @param right - Массив байт
	 * @return true, если данные равны
	 */
	public boolean equals( Binary right )
	{
		if( right == null )
		{
			return false;
		}
		return equals( right.getDataRef(), right.size() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сравнить с HEX-строкой.
	 * @param hexStr - HEX-строка
	 * @return true, если данные равны
	 */
	public boolean equals( String hexStr )
	{
		if( hexStr == null )
		{
			return false;
		}
		return equals( new Binary( hexStr ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сравнить с массивом байт.
	 * @param data - Массив байт
	 * @return true, если данные равны
	 */
	public boolean equals( byte[] data )
	{
		return equals( data, data.length );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	private boolean equals( byte[] data, int len )
	{
		if( mData == data )
		{
			return true;
		}

		if( data == null )
		{
			return false;
		}

		if( size() != len )
		{
			return false;
		}

		byte[] this_data = mData;
		for( int i = 0; i < len; ++i )
		{
			if( this_data[ i ] != data[ i ] )
			{
				return false;
			}
		}
		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int hashCode()
	{
		byte[] arr = mData;
		int size = mSize;
		int hash = 0;
		for( int i = 0; i < size; ++i )
		{
			hash = 31 * hash + arr[ i ];
		}
		return hash;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выделить память указанного размера, чтобы не выделять многократно при добавлении данных.
	 * @return ссылка на себя.
	 */
	public Binary reserve( int capacity )
	{
		MUST( capacity >= 0, "Размер массива не может быть отрицательным" );
		ensureCapacity( capacity );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Изменить размер массива на {@code newSize}. Лишние байты отбрасываются, недостающие - заполняются {@code val}.
	 * @param newSize - Новый размер массива
	 * @param val - Байт-заполнитель (учитывается только младший байт).
	 */
	public void resize( int newSize, int val )
	{
		MUST( newSize >= 0, "Размер массива не может быть отрицательным" );

		int oldSize = mSize;
		ensureCapacity( newSize );

		if( newSize > oldSize )
		{
			Arrays.fill( mData, oldSize, newSize, (byte)(val & 0xFF) );
		}
		mSize = newSize;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Изменить размер массива на {@code newSize}. Лишние байты отбрасываются, недостающие - заполняются нулями.
	 * @param newSize - Новый размер массива
	 */
	public void resize( int newSize )
	{
		resize( newSize, 0 );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать размер массива, не трогая содержимое.
	 * newSize не может быть больше capacity().
	 * @param newSize - Новый размер массива.
	 */
	public void setSize( int newSize )
	{
		MUST( (newSize >= 0) && (newSize <= mData.length), "Wrong size for Binary.setSize()" );
		mSize = newSize;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Изменить порядок байтов в массиве на обратный.
	 * @return Ссылка на себя.
	 */
	public Binary reverse()
	{
		int left = 0;
		int right = mSize - 1;

		while( left < right )
		{
			byte temp = mData[ left ];
			mData[ left ] = mData[ right ];
			mData[ right ] = temp;

			++left;
			--right;
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать копию части массива.<br>
	 * @param offset - Смещение начала фрагмента.
	 * @param partSize - размер части.
	 */
	public Binary slice( int offset, int partSize )
	{
		MUST( (offset + partSize) <= mSize, "Wrong 'offset' or 'partSize' in Binary.slice()" );
		return new Binary( mData, offset, partSize );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать копию части массива. Первые partSize байт.
	 */
	public Binary first( int partSize )
	{
		MUST( partSize <= mSize, "Wrong 'partSize' in Binary.first()" );
		return new Binary( mData, 0, partSize );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать копию части массива. Последние partSize байт.
	 */
	public Binary last( int partSize )
	{
		MUST( partSize <= mSize, "Wrong 'partSize' in Binary.last()" );
		return new Binary( mData, mSize - partSize, partSize );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Побитовый XOR, такой что {@code this ^= right}.<br>Размеры this и right должны быть равны.
	 * @param right - Массив, с которым выполнится XOR
	 * @return Ссылка на себя
	 */
	public Binary xor( Binary right )
	{
		int sz = size();
		MUST( sz == right.size(), "Длины массивов в операторе 'xor' должны быть равны" );

		byte[] this_data = mData;
		byte[] right_data = right.mData;
		for( int i = 0; i < sz; ++i )
		{
			this_data[ i ] ^= right_data[ i ];
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Побитовый OR, такой что {@code this |= right}.<br>Размеры this и right должны быть равны.
	 * @param right - Массив, с которым выполнится OR
	 * @return Ссылка на себя
	 */
	public Binary or( Binary right )
	{
		int size = size();
		MUST( size == right.size(), "Длины массивов в операторе 'or' должны быть равны" );

		byte[] this_data = mData;
		byte[] right_data = right.mData;
		for( int i = 0; i < size; ++i )
		{
			this_data[ i ] |= right_data[ i ];
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Побитовый AND, такой что {@code this &= right}.<br>Размеры this и right должны быть равны.
	 * @param right - Массив, с которым выполнится AND
	 * @return Ссылка на себя
	 */
	public Binary and( Binary right )
	{
		int size = size();
		MUST( size == right.size(), "Длины массивов в операторе 'and' должны быть равны" );

		byte[] this_data = mData;
		byte[] right_data = right.mData;
		for( int i = 0; i < size; ++i )
		{
			this_data[ i ] &= right_data[ i ];
		}
		return this;
	}


	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать байт по заданному индексу, считая байт знаковым.
	 * @param index - Индекс
	 */
	public int getI( int index )
	{
		MUST( index < mSize, "Выход за границы Binary" );
		return mData[ index ];
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать байт по заданному индексу с преобразованием байта к int-у, считая байт беззнаковым.
	 * @param index - Индекс
	 */
	public int get( int index )
	{
		MUST( index < mSize, "Выход за границы Binary" );
		return mData[ index ] & 0xFF;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Записать байт {@code value} по заданному индексу {@code index}.
	 * @param index - Индекс
	 * @param value - Значение
	 */
	public void set( int index, byte value )
	{
		MUST( index < mSize, "Выход за границы Binary" );
		mData[ index ] = value;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Записать байт {@code value} по заданному индексу {@code index}.
	 * @param index - Индекс
	 * @param value - Значение (используется младший байт)
	 */
	public void set( int index, int value )
	{
		MUST( index < mSize, "Выход за границы Binary" );
		mData[ index ] = (byte)(value & 0xFF);
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Записать часть входного массива в этот объект по заданному смещению.
	 * @param destOffset - смещение в этом объекте, по которому нужно записать данные.
	 * @param data - Массив байт.
	 * @param srcOffset - Смещение начала данных в массиве data.
	 * @param len - размер записываемых данных.
	 */
	public void set( int destOffset, byte[] data, int srcOffset, int len )
	{
		MUST( (destOffset + len) <= mSize, "Выход за границы Binary" );
		System.arraycopy( data, srcOffset, mData, destOffset, len );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Записать часть входного массива в этот объект по заданному смещению.
	 * @param destOffset - смещение в этом объекте, по которому нужно записать данные.
	 * @param data - Массив байт.
	 * @param srcOffset - Смещение начала данных в массиве data.
	 * @param len - размер записываемых данных.
	 */
	public void set( int destOffset, Binary data, int srcOffset, int len )
	{
		MUST( (destOffset + len) <= mSize, "Выход за границы Binary" );
		MUST( (srcOffset + len) <= data.size(), "Выход за границы Binary" );
		System.arraycopy( data.getDataRef(), srcOffset, mData, destOffset, len );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Записать число {@code value} (short = 2 байта) по смещению {@code offset} в формате BigEndian.
	 * @param offset - Смещение.
	 * @param value - Значение short (используются младшие 2 байта)
	 */
	public void setU16( int offset, int value )
	{
		MUST( (offset + 2) <= mSize, "Выход за границы Binary" );
		mData[ offset++ ] = (byte)(value >>> 8);
		mData[ offset   ] = (byte)(value & 0xFF);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать беззнаковое число (short = 2 байта) по смещению {@code offset} в формате BigEndian.
	 * @param offset - Смещение
	 */
	public int getU16( int offset )
	{
		MUST( (offset + 2) <= mSize, "Выход за границы Binary" );
		return ((mData[ offset ] << 8) | (mData[ offset + 1 ] & 0xFF)) & 0xFFFF;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать беззнаковое число (4 байта) по смещению {@code offset} в BigEndian.
	 * @param offset - Смещение
	 */
	public long getU32( int offset )
	{
		return getIntBE( offset ) & 0xFFFFFFFFL;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Записать число {@code val} (int = 4 байта) по смещению {@code offset} в BigEndian.
	 * @param value - Значение.
	 */
	public void setInt( int offset, int value )
	{
		MUST( (offset + 4) <= mSize, "Выход за границы Binary" );
		mData[ offset     ] = (byte)(value >>> 24);
		mData[ offset + 1 ] = (byte)(value >>> 16);
		mData[ offset + 2 ] = (byte)(value >>>  8);
		mData[ offset + 3 ] = (byte)(value & 0xFF);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Записать число {@code val} (int = 4 байта) по смещению {@code offset} в LittleEndian.
	 * @param value - Значение.
	 */
	public void setIntLE( int offset, int value )
	{
		MUST( (offset + 4) <= mSize, "Выход за границы Binary" );
		mData[ offset     ] = (byte)(value & 0xFF);
		mData[ offset + 1 ] = (byte)(value >>>  8);
		mData[ offset + 2 ] = (byte)(value >>> 16);
		mData[ offset + 3 ] = (byte)(value >>> 24);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Записать в массив long по смещению offset в BigEndian.
	 * @param l - Число.
	 */
	public void setLong( int offset, long l )
	{
		MUST( (offset + 8) <= mSize, "Выход за границы Binary" );

		int i1 = (int)(l >>> 32);
		int i2 = (int)(l & 0xFFFFFFFF);

		mData[ offset++ ] = (byte)(i1 >>> 24);
		mData[ offset++ ] = (byte)(i1 >>> 16);
		mData[ offset++ ] = (byte)(i1 >>>  8);
		mData[ offset++ ] = (byte)(i1 & 0xFF);
		mData[ offset++ ] = (byte)(i2 >>> 24);
		mData[ offset++ ] = (byte)(i2 >>> 16);
		mData[ offset++ ] = (byte)(i2 >>>  8);
		mData[ offset   ] = (byte)(i2 & 0xFF);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Записать в массив long по смещению offset в LittleEndian.
	 * @param l - Число.
	 */
	public void setLongLE( int offset, long l )
	{
		MUST( (offset + 8) <= mSize, "Выход за границы Binary" );

		int hi = (int)(l >>> 32);
		int lo = (int)(l & 0xFFFFFFFF);

		mData[ offset     ] = (byte)(lo & 0xFF);
		mData[ offset + 1 ] = (byte)(lo >>>  8);
		mData[ offset + 2 ] = (byte)(lo >>> 16);
		mData[ offset + 3 ] = (byte)(lo >>> 24);
		offset += 4;
		mData[ offset     ] = (byte)(hi & 0xFF);
		mData[ offset + 1 ] = (byte)(hi >>>  8);
		mData[ offset + 2 ] = (byte)(hi >>> 16);
		mData[ offset + 3 ] = (byte)(hi >>> 24);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать число (int = 4 байта) по смещению {@code offset} в формате BigEndian.
	 */
	public int getIntBE( int offset )
	{
		MUST( (offset + 4) <= mSize, "Выход за границы Binary" );

		return (mData[ offset     ] << 24)
			| ((mData[ offset + 1 ] & 0xFF) << 16)
			| ((mData[ offset + 2 ] & 0xFF) << 8)
			|  (mData[ offset + 3 ] & 0xFF);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать число (int = 4 байта) по смещению {@code offset} в формате LittleEndian.
	 */
	public int getIntLE( int offset )
	{
		MUST( (offset + 4) <= mSize, "Выход за границы Binary" );

		return (mData[ offset ] & 0xFF)
			| ((mData[ offset + 1 ] & 0xFF) << 8)
			| ((mData[ offset + 2 ] & 0xFF) << 16)
			| (mData[ offset + 3 ] << 24);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать число (long = 8 байт) по смещению {@code offset} в формате BigEndian.
	 */
	public long getLong( int offset )
	{
		MUST( (offset + 8) <= mSize, "Выход за границы Binary" );

		int i1 = (mData[ offset++ ] << 24)
			  | ((mData[ offset++ ] & 0xFF) << 16)
			  | ((mData[ offset++ ] & 0xFF) << 8)
			  |  (mData[ offset++ ] & 0xFF);
		int i2 = (mData[ offset++ ] << 24)
			  | ((mData[ offset++ ] & 0xFF) << 16)
			  | ((mData[ offset++ ] & 0xFF) << 8)
			  |  (mData[ offset++ ] & 0xFF);
			
		return ((long)i1 << 32) | (i2 & 0xFFFFFFFFL);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать число (long = 8 байт) по смещению {@code offset} в формате LittleEndian.
	 */
	public long getLongLE( int offset )
	{
		MUST( (offset + 8) <= mSize, "Выход за границы Binary" );

		int lo = (mData[ offset ] & 0xFF)
			  | ((mData[ offset + 1 ] & 0xFF) << 8)
			  | ((mData[ offset + 2 ] & 0xFF) << 16)
			  |  (mData[ offset + 3 ] << 24);
		offset += 4;
		int hi = (mData[ offset ] & 0xFF)
				  | ((mData[ offset + 1 ] & 0xFF) << 8)
				  | ((mData[ offset + 2 ] & 0xFF) << 16)
				  |  (mData[ offset + 3 ] << 24);
		return ((long)hi << 32) | (lo & 0xFFFFFFFFL);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Интерпретировать массив байтов как беззнаковое 16-битное целое.
	 * @return Число (значащие два младших байта)
	 */
	public int asU16()
	{
		switch( size() )
		{
			case 0:
				return 0;
			case 1:
				return get( 0 );
			case 2:
				return getU16( 0 );
			default:
				MUST( false, "array size must be less or equal than number type size" );
		}
		return 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Интерпретировать массив байтов как беззнаковое 32-битное целое.
	 * @return Число (значащие четыре младших байта)
	 */
	public long asU32()
	{
		switch( size() )
		{
			case 0:
			case 1:
			case 2:
				return asU16();
			case 3:
				return ((mData[ 0 ] & 0xFF) << 16) | ((mData[ 1 ] & 0xFF) << 8) | (mData[ 2 ] & 0xFF);
			case 4:
				return getIntBE( 0 ) & 0xFFFFFFFFL;
			default:
				MUST( false, "array size must be less or equal than number type size" );
		}
		return 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void randomImpl( Random rnd, int size )
	{
		resize( size );
		for( int i = 0; i < size; ++i )
		{
			mData[ i ] = (byte)rnd.nextInt( 256 );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Заполнить массив случайными данными.<br>Размер массива станет {@code size}
	 * @param size - Размер массива
	 * @return Ссылка на себя
	 */
	public Binary random( int size )
	{
		if( this.rand == null )
		{
			this.rand = new Random( System.nanoTime() );
		}

		randomImpl( this.rand, size );

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary randomSecure( int size )
	{
		if( this.randSecure == null )
		{
			try
			{
				this.randSecure = new SecureRandom();
			}
			catch( Throwable ex )
			{
				THROW( ex );
			}
		}

		randomImpl( this.randSecure, size );

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Инкрементировать массив на 1.<br>
	 * Содержимое массива интерпретируется как беззнаковое целое в формате BigEndian.
	 * @return ссылка на себя.
	 */
	public Binary increment()
	{
		if( empty() )
			return this;

		int i = size();
		do
		{
			--i;
			set( i, get( i ) + 1 );
		}
		while( (i != 0) && (get( i ) == 0) );

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Декрементировать массив на 1.<br>
	 * Содержимое массива интерпретируется как беззнаковое целое в формате BigEndian.
	 * @return ссылка на себя.
	 */
	public Binary decrement()
	{
		if( empty() )
			return this;

		int i = size();
		do
		{
			--i;
			set( i, get( i ) - 1 );
		}
		while( (i != 0) && (get( i ) == 0xFF) );
		
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить значение бита в указанном байте.
	 * @param index - номер байта.
	 * @param bitNum - номер бита в байте [0-7]. Младший бит - 0, старший бит - 7.
	 * @preturn True - бит взведен, false - сброшен.
	 */
	public boolean getBit( int index, int bitNum )
	{
		MUST( (bitNum >= 0) && (bitNum <= 7), "Wrong 'bitNum'" );
		return (get( index ) & (1 << bitNum)) != 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Установить бит в заданое значение в указанном байте.
	 * @param index - номер байта.
	 * @param bitNum - номер бита в байте [0-7]. Младший бит - 0, старший бит - 7.
	 * @param bitValue - true - взвести бит, false - сбросить.
	 */
	public void writeBit( int index, int bitNum, boolean bitValue )
	{
		if( bitValue )
		{
			setBit( index, bitNum );
		}
		else
		{
			resetBit( index, bitNum );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Взвести бит в указанном байте.
	 * @param index - номер байта.
	 * @param bitNum - номер бита в байте [0-7]. Младший бит - 0, старший бит - 7.
	 */
	public void setBit( int index, int bitNum )
	{
		MUST( (bitNum >= 0) && (bitNum <= 7), "Wrong 'bitNum'" );
		MUST( index < mSize, "Binary index out of bounds" );
		mData[ index ] |= (1 << bitNum);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сбросить бит в указанном байте.
	 * @param index - номер байта.
	 * @param bitNum - номер бита в байте [0-7]. Младший бит - 0, старший бит - 7.
	 */
	public void resetBit( int index, int bitNum )
	{
		MUST( (bitNum >= 0) && (bitNum <= 7), "Wrong 'bitNum'" );
		MUST( index < mSize, "Binary index out of bounds" );
		mData[ index ] &= ~(1 << bitNum);
	}

	//------------------------------------------------------------------------------------------------------------------
	/**
	 * Преобразовать строку в байтовый массив с заданной кодировкой.
	 * Например: Utils.UTF8 или Charset.forName( "ISO-8859-5" ).
	 * @return this.
	 */
	public Binary fromString( String str, Charset charSet )
	{
		assign( str.getBytes( charSet ) );
		return this;
	}

	//------------------------------------------------------------------------------------------------------------------
	/**
	 * Преобразовать строку в байтовый массив с кодировкой UTF-8.
	 * @return this.
	 */
	public Binary fromUTF8( String str )
	{
		assign( str.getBytes( Strings.UTF8 ) );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Преобразовать байтовый массив в строку с заданной кодировкой.
	 * Например: Utils.UTF8 или Charset.forName( "ISO-8859-5" )
	 */
	public String asString( Charset charSet )
	{
		return new String( mData, 0, size(), charSet );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Преобразовать байтовый массив в строку с кодировкой UTF-8.
	 */
	public String asUTF8()
	{
		return new String( mData, 0, size(), Strings.UTF8 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Загрузить из файла данные как массив байт. Данные массива заменятся загруженными.
	 */
	public Binary loadFromFile( String fileName )
	{
		try
		(
			FileInputStream fis = new FileInputStream( fileName );
			BufferedInputStream buf_in = new BufferedInputStream( fis );
		)
		{
			int size = buf_in.available();
			MUST( size < Integer.MAX_VALUE, "Размер файла должен быть меньше максимального размера int" );

			ensureCapacity( size );
			buf_in.read( getDataRef() );
			mSize = size;
		}
		catch( IOException e )
		{
			THROW( e.toString() );
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сохранить массив байт как файл. Если указанный файл существует, он будет перезаписан.
	 */
	public void saveToFile( String fileName )
	{
		try
		(
			FileOutputStream fos = new FileOutputStream( fileName );
			BufferedOutputStream buf_out = new BufferedOutputStream( fos );
		)
		{
			buf_out.write( getDataRef(), 0, size() );
			buf_out.flush();
		}
		catch( IOException e )
		{
			THROW( e.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int compareTo( Binary that )
	{
		int size = Math.min( mSize, that.mSize );
		for( int i = 0; i < size; ++i )
		{
			int cmp = Integer.compare( this.get( i ), that.get( i ) );
			if( cmp != 0 )
				return cmp;
		}
		return this.mSize - that.mSize;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать Binary нулевого размера.
	 */
	public static Binary Bin()
	{
		return new Binary();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать Binary размером {@code size} байт, заполненный нулевыми значениями.
	 * @param size - Размер
	 */
	public static Binary Bin( int size )
	{
		return new Binary( size );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать Binary размером {@code size} байт, заполненным значениями {@code value}.
	 * @param size - Размер
	 * @param value - Значение (используется младший байт)
	 */
	public static Binary Bin( int size, int value )
	{
		return new Binary( size, value );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать Binary из массива байт.
	 * @param data - Массив байт
	 */
	public static Binary Bin( byte[] data )
	{
		return new Binary( data );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать новый Binary из HEX-строки.
	 */
	public static Binary Bin( String hexStr )
	{
		return new Binary( hexStr );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сконкатенировать несколько Binary в один.
	 */
	public static Binary Bin( final Binary... bins )
	{
		Binary res = new Binary().reserve( 100 );
		for( Binary b : bins )
			res.add( b );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Побитовый XOR.<br>
	 * Создается новый Binary, равный {@code (left ^ right)}. Размеры left и right должны быть равны.
	 * @param left - Массив байт
	 * @param right - Массив байт
	 */
	public static Binary xor( Binary left, Binary right )
	{
		return new Binary( left ).xor( right );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Побитовый OR.<br>
	 * Создается новый Binary, равный {@code (left | right)}. Размеры left и right должны быть равны.
	 * @param left - Массив байт
	 * @param right - Массив байт
	 */
	public static Binary or( Binary left, Binary right )
	{
		return new Binary( left ).or( right );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Побитовый AND.<br>
	 * Создается новый Binary, равный {@code (left & right)}. Размеры left и right должны быть равны.
	 * @param left - Массив байт
	 * @param right - Массив байт
	 */
	public static Binary and( Binary left, Binary right )
	{
		return new Binary( left ).and( right );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Преобразовать целое число в массив байтов. Формат BigEndian.
	 * @param num - Число.
	 * @param minLen - Минимальная длина массива. Слева дополняется нулями.
	 * @return Новый Binary
	 */
	public static Binary Num_Bin( long num, int minLen )
	{
		final int bufSize = 8;
		byte[] buf = new byte[ bufSize ];

		// Запишем в buf значащие байты числа num в big-endian, заодно считаем длину.
		int len = 0;

		do
		{
			++len;
			buf[ bufSize - len ] = (byte)(num & 0xFF);
			num >>>= 8;
		}
		while( num != 0 );

		// Если выравнивать не нужно, то возвращаем Binary сразу
		if( minLen <= len )
		{
			return new Binary( buf, bufSize - len, len );
		}
		Binary b = new Binary( minLen, 0 ); // Заполняем Binary нужной длины нулями
		System.arraycopy( buf, bufSize - len, b.mData, minLen - len, len );
		return b;
	}

	//------------------------------------------------------------------------------------------------------------------
	/**
	 * Получить значение Binary != null из Map.
	 */
	public static <T> Binary getBinSafe( T key, Map<T, Binary> map )
	{
		Binary val = map.get( key );
		return val != null ? val : new Binary();
	}

}
