// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.format;

import org.denom.Binary;
import org.denom.Int;

import static org.denom.Ex.MUST;

/**
 * Парсинг и формирование BER-TLV-записей.
 */
public class BerTLV
{
	/**
	 * Тег BER-TLV записи. Значение тега - unsigned.
	 */
	public int tag;

	/**
	 * Данные BER-TLV записи.
	 */
	public final Binary value;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Пустая BER-TLV запись.
	 */
	public BerTLV()
	{
		tag = 0;
		value = new Binary();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * BER-TLV запись на основе байтового массива.
	 * @param bin - Массив байт.
	 */
	public BerTLV( final Binary bin )
	{
		this();
		assign( bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * BER-TLV запись в HEX-строке.
	 */
	public BerTLV( String hexStr )
	{
		this();
		assign( hexStr );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Копия объекта BER-TLV.
	 */
	@Override
	public BerTLV clone()
	{
		BerTLV result = new BerTLV();
		result.tag = tag;
		result.value.assign( value );
		return result;
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Сравнить с другим BER-TLV.
	 */
	@Override
	public boolean equals( Object other )
	{
		if( other == null )
		{
			return false;
		}
		if( other == this )
		{
			return true;
		}

		BerTLV b = other instanceof BerTLV ? (BerTLV)other : null;

		if( (b != null) && (this.tag == b.tag) && this.value.equals( b.value ) )
		{
			return true;
		}
		
		return false;
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Очистка полей объекта BER-TLV.
	 */
	public void clear()
	{
		tag = 0;
		value.clearMem();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Является ли запись шаблоном, определяется по флагу в теге.
	 */
	public boolean isConstructed()
	{
		return isTagConstructed( tag );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return BER-TLV запись в виде байтового массива.
	 */
	public Binary toBin()
	{
		if( tag != 0 )
		{
			return Tlv( tag, value );
		}
		return new Binary();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return BER-TLV запись в виде строки.
	 */
	@Override
	public String toString()
	{
		return toBin().Hex();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Заполнение полей BER-TLV записи на основе байтового массива.
	 * @param bin - Массив байт.
	 */
	public void assign( final Binary bin )
	{
		clear();
		MUST( isTLV( bin ), "Некорректная BER-TLV запись" );
		parseTLV( bin, new Int( 0 ), this );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void assign( String hexStr )
	{
		assign( new Binary( hexStr ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return true, если запись задана.
	 */
	public boolean exists()
	{
		return tag != 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Найти в поле value (считаем его списком BER-TLV) запись с заданным тегом.
	 * В списке может быть несколько записей с тегом {@code tag}.
	 * @param tag - Тег записи.
	 * @param nth - какая по счёту запись нужна (считаем от 1).
	 * @return Если запись не является шаблоном/constructed или запись не найдена, возвращается пустой объект BerTLV.
	 */
	public BerTLV find( int tag, int nth )
	{
		if( !isConstructed() )
		{
			return new BerTLV();
		}
		return new BerTLVList( value ).find( tag, nth );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Найти в списке первую запись с заданным тегом Tag.
	 * @param Tag - Тег записи.
	 * @return Искомая запись, или пустой объект BerTLV если запись не найдена.
	 */
	public BerTLV find( int Tag )
	{
		return find( Tag, 1 );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Найти в поле value (считаем его списком BER-TLV) запись по заданному пути.
	 * 
	 * @param path
	 *            Путь - это теги, разделённые слешем. Пример - "6F / 84".
	 * @return Если запись не является шаблоном/constructed или запись не найдена, возвращается
	 *         пустой объект BerTLV
	 */
	public BerTLV find( String path )
	{
		if( !isConstructed() )
		{
			return new BerTLV();
		}
		return new BerTLVList( value ).find( path );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать поле Tag из байтового массива bin по смещению offset. <br>
	 * Если поле задано корректно, результат в Tag, offset смещается на длину поля Tag.
	 * 
	 * @param bin
	 *            Массив байт
	 * @param offset
	 *            [in/out] Смещение
	 * @param tag_parsed
	 *            [out] Сюда считывается тег
	 * @return true - поле задано корректно, иначе - false.
	 */
	public static boolean parseTag( final Binary bin, Int offset, Int tag_parsed )
	{
		int size = bin.size();
		int offs = offset.val;

		if( offs >= size )
		{
			return false;
		}

		int b1 = bin.get( offs++ );

		if( (b1 & 0x1F) != 0x1F )
		{	// младшие 5 бит не равны 11111, значит тег 1-байтовый
			tag_parsed.val = b1;
			offset.val = offs;
			return tag_parsed.val != 0; // Нулевой тег считается невалидным
		}

		// тег больше, чем 1 байт
		if( offs == size )
		{	// в массиве недостаточно байтов
			return false;
		}

		int b2 = bin.get( offs++ );

		// Второй байт равный 0x01..0x1E - некорректный по стандарту, но используется в EMV,
		// поэтому принимаем такие теги.
		if( (b2 == 0x00) || (b2 == 0x80) )
		{
			return false;
		}

		if( b2 < 0x80 )
		{	// тег 2-байтовый
			tag_parsed.val = (b1 << 8) | b2;
			offset.val = offs;
			return true;
		}

		if( offs == size )
		{	// в массиве недостаточно байтов
			return false;
		}

		int b3 = bin.get( offs++ );
		
		if( b3 > 0x7F )
		{	// Тег длиной больше 3 байт - не валиден по ISO 7816-4.
			return false;
		}

		// Тег 3-байтовый
		tag_parsed.val = (b1 << 16) | (b2 << 8) | b3;
		offset.val = offs;
		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать поле Length из байтового массива bin по смещению offset.<br>
	 * Если поле задано корректно, то результат в Length, offset смещается на длину поля Length.
	 * 
	 * @param bin
	 *            Массив байт
	 * @param offset
	 *            [in/out] Смещение
	 * @param len_parsed
	 *            [out] Сюда считывается длина поля
	 * @return true - поле задано корректно, иначе - false.
	 */
	public static boolean parseLength( final Binary bin, Int offset, Int len_parsed )
	{
		len_parsed.val = 0;

		if( offset.val >= bin.size() )
		{
			return false;
		}

		int b1 = bin.get( offset.val );
		if( b1 < 0x80 )
		{	// Поле длины - однобайтовое
			len_parsed.val = b1;
			++offset.val;
			return true;
		}

		if( (b1 == 0x80) || ( b1 > 0x84) )
		{	// Некорректное поле Len, первый байт неправильно задан.
			return false;
		}

		// Поле длины должно быть 2-5 байт, т.к. первый байт 0x81..0x84.
		int l = b1 & 0x7F; // 1..4
		if( (offset.val + 1 + l) > bin.size() )
		{	// В массиве недостаточно байт
			return false;
		}

		// Поле задано корректно, вычисляем Length
		++offset.val;
		while( l > 0 )
		{
			len_parsed.val <<= 8;
			len_parsed.val |= bin.get( offset.val );
			++offset.val;
			--l;
		}
		return len_parsed.val >= 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать BER-TLV запись из байтового массива bin по смещению offset. <br>
	 * Поле Value не парсится. offset смещается на длину записи.
	 * 
	 * @param bin
	 *            Массив байт
	 * @param offset
	 *            [in/out] Смещение
	 * @param rec
	 *            [out] Сюда считывается запись BER-TLV
	 * @return true - запись задана корректно, иначе - false.
	 */
	public static boolean parseTLV( final Binary bin, Int offset, BerTLV rec )
	{
		Int offs = new Int( offset.val );

		Int tag_parsed = new Int( 0 );
		if( !parseTag( bin, offs, tag_parsed ) )
		{
			return false;
		}

		Int len_parsed = new Int( 0 );
		if( !parseLength( bin, offs, len_parsed ) )
		{
			return false;
		}

		if( (offs.val + len_parsed.val) > bin.size() )
		{
			return false;
		}

		rec.tag = tag_parsed.val;
		rec.value.assign( bin, offs.val, len_parsed.val );
		offset.val = offs.val + len_parsed.val;
		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param tag
	 *            Проверяемый тег
	 * @return Является ли Tag шаблоном
	 */
	public static boolean isTagConstructed( int tag )
	{
		if( tag == 0 )
		{
			return false;
		}
	
		while( (tag & 0xFF00) != 0 )
		{	// получаем в младшем байте старший байт
			tag >>>= 8;
		}

		return (tag & 0x20) != 0; // 6-ой бит показывает, является ли запись constucted или primitive
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param bin
	 *            Массив байт
	 * @return Является ли байтовый массив BER-TLV записью (парсятся все вложенные записи).
	 */
	public static boolean isTLV( final Binary bin )
	{
		BerTLV rec = new BerTLV();
		Int offset = new Int( 0 );
		if( !parseTLV( bin, offset, rec ) )
		{
			return false;
		}
		if( offset.val != bin.size() )
		{
			return false;
		}

		if( rec.isConstructed() )
		{
			return isTLVList( rec.value );
		}
		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param bin
	 *            Массив байт
	 * @return Является ли байтовый массив списком BER-TLV записей (парсятся все вложенные записи).
	 */
	public static boolean isTLVList( final Binary bin )
	{
		Int offset = new Int( 0 );
		BerTLV rec = new BerTLV();

		while( (offset.val < bin.size()) && parseTLV( bin, offset, rec ) )
		{
			if( rec.isConstructed() )
			{
				if( !isTLVList( rec.value ) )
				{
					return false;
				}
			}
		}

		return offset.val == bin.size();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сформировать поле Tag BER-TLV-записи и добавить его к {@code bin}.
	 * @param bin - [in/out] Байтовый массив.
	 * @param tag - Тег.
	 */
	public static void appendTlvTag( Binary bin, int tag )
	{
		if( (tag >>> 8) != 0 )
		{
			if( (tag >>> 16) != 0 )
			{
				if( (tag >>> 24) != 0 )
				{
					bin.add( tag >>> 24 );
				}
				bin.add( tag >>> 16 );
			}
			bin.add( tag >>> 8 );
		}
		bin.add( tag );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сформировать поле Len BER-TLV-записи и добавить его к {@code bin}.
	 * @param bin - [in/out] Байтовый массив.
	 * @param len - Длина.
	 */
	public static void appendTlvLen( Binary bin, int len )
	{
		// Формирование поля Len по стандарту
		if( len >= 0x80 )
		{
			if( (len >>> 8) != 0 )
			{
				if( (len >>> 16) != 0 )
				{
					if( (len >>> 24) !=0 )
					{
						bin.add( 0x84 );
						bin.add( len >>> 24 );
					}
					else
					{
						bin.add( 0x83 );
					}
					bin.add( len >>> 16 );
				}
				else
				{
					bin.add( 0x82 );
				}
				bin.add( len >>> 8 );
			}
			else
			{
				bin.add( 0x81 );
			}
		}
		bin.add( len & 0xFF );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сформировать запись BER-TLV в виде массива байт.
	 * @param tag - Тег.
	 * @param value - Поле Value.
	 * @return BER-TLV запись.
	 */
	public static Binary Tlv( int tag, final Binary value )
	{
		Binary res = new Binary().reserve( 4 + value.size() );
		appendTlvTag( res, tag );
		appendTlvLen( res, value.size() );
		res.add( value );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сформировать запись BER-TLV в виде массива байт.
	 * @param tag - Тег.
	 * @param value - Один или несколько Binary (конкатенируются).
	 * @return BER-TLV запись.
	 */
	public static Binary Tlv( int tag, final Binary... value )
	{
		Binary res = new Binary().reserve( 50 );

		Binary val = Binary.Bin( value );
		appendTlvTag( res, tag );
		appendTlvLen( res, val.size() );
		res.add( val );

		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static Binary Tlv( int tag, String valHex )
	{
		return Tlv( tag, new Binary( valHex ) );
	}
}
