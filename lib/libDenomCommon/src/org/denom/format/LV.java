// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.format;

import java.util.ArrayList;

import org.denom.*;

import static org.denom.Ex.MUST;
import static org.denom.Binary.Bin;

/**
 * Формирование и парсинг LV-списков.
 *
 * LV-запись - байтовый массив, конкатенация двух полей: Length и Value, где
 * Length – длина Value в байтах (беззнаковое целое 1,2,4-х-байтовое число в BigEndian),
 * может содержать только нули.
 * Value – произвольные байты, поле может отсутствовать.
 * 
 * LV-список – конкатенация объектов LV.
 * 
 * LV1, LV2, LV4 - число задаёт размер поля Length.
 */
public final class LV
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать список значений в список LV1-записей.
	 * @return список LV-записей.
	 */
	public static Binary LV1( final Binary... values )
	{
		Binary res = new Binary().reserve( 200 );
		for( Binary value : values )
		{
			MUST( Int.isU8( value.size() ), "Too long Value for LV1" );
			res.add( value.size() );
			res.add( value );
		}
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать список значений в список LV2-записей.
	 * @return список LV-записей.
	 */
	public static Binary LV2( final Binary... values )
	{
		Binary res = new Binary().reserve( 200 );
		for( Binary value : values )
		{
			MUST( Int.isU16( value.size() ), "Too long Value for LV2" );
			res.addU16( value.size() );
			res.add( value );
		}
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать список значений в список LV4-записей.
	 * @return список LV-записей.
	 */
	public static Binary LV4( final Binary... values )
	{
		Binary res = new Binary().reserve( 200 );
		for( Binary value : values )
		{
			res.addInt( value.size() );
			res.add( value );
		}
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Len (U8) | value.
	 */
	public static Binary LV1( final Binary value )
	{
		MUST( Int.isU8( value.size() ), "Too long Value for LV1" );
		Binary res = new Binary().reserve( value.size() + 1 );
		res.add( value.size() );
		res.add( value );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Len (U16) | value.
	 */
	public static Binary LV2( final Binary value )
	{
		MUST( Int.isU16( value.size() ), "Too long Value for LV2" );
		Binary res = new Binary().reserve( value.size() + 2 );
		res.addU16( value.size() );
		res.add( value );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Len (U24) | value.
	 */
	public static Binary LV3( final Binary value )
	{
		MUST( Int.isU24( value.size() ), "Too long Value for LV3" );
		Binary res = new Binary().reserve( value.size() + 3 );
		res.addU24( value.size() );
		res.add( value );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Len (U32) | value.
	 */
	public static Binary LV4( final Binary value )
	{
		MUST( Int.isU24( value.size() ), "Too long Value for LV4" );
		Binary res = new Binary().reserve( value.size() + 4 );
		res.addInt( value.size() );
		res.add( value );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать список строк в список LV4-записей.
	 * Строки кодируются в UTF-8.
	 * @return список LV-записей.
	 */
	public static Binary LV4Strings( final String... strings )
	{
		Binary res = new Binary().reserve( 200 );
		for( String s : strings )
		{
			Binary value = Bin().fromUTF8( s );
			res.addInt( value.size() );
			res.add( value );
		}
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить LV-список.
	 * @return - список значений.
	 */
	private static Binary[] parseLV( int lengthSize, final Binary bin )
	{
		ArrayList<Binary> list = new ArrayList<Binary>();

		int size = bin.size();
		int offset = 0;
		while( offset < size )
		{
			MUST( (offset + lengthSize) <= size, "Incorrect LV2 List" );
			int len = (int)bin.slice( offset, lengthSize ).asU32();
			offset += lengthSize;
			MUST( (len >= 0) && (offset + len) <= size, "Incorrect LV2 List" );

			list.add( new Binary( bin.getDataRef(), offset, len ) );
			offset += len;
		}

		return list.toArray( new Binary[ list.size() ] );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить LV2-список.
	 * @return - список значений.
	 */
	public static Binary[] parseLV1( final Binary bin )
	{
		return parseLV( 1, bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить LV2-список.
	 * @return - список значений.
	 */
	public static Binary[] parseLV2( final Binary bin )
	{
		return parseLV( 2, bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить LV4-список.
	 * @return - список значений.
	 */
	public static Binary[] parseLV4( final Binary bin )
	{
		return parseLV( 4, bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить список строк в формате LV4.
	 * Строки должны быть в UTF-8.
	 * @return - список строк.
	 */
	public static String[] parseLV4Strings( final Binary data )
	{
		Binary[] bins = parseLV4( data );
		String[] strings = new String[ bins.length ];

		int i = 0;
		for( Binary b : bins )
		{
			strings[ i++ ] = b.asUTF8();
		}
		return strings;
	}
	
}