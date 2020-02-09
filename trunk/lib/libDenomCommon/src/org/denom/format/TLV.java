// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.format;

import java.util.*;

import org.denom.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * TLV4 (TLV4-запись) –  байтовый массив, конкатенация трёх полей: Tag, Length, Value, где
 *  Tag – метка/идентификатор (беззнаковое целое 4-х-байтовое число в BigEndian);
 *  Length – длина Value в байтах (беззнаковое целое 4-х-байтовое число в BigEndian), может содержать только нули;
 *  Value – произвольные байты, поле может отсутствовать.
 * 
 * TLV-список – конкатенация объектов TLV.
 * 
 * TLV2, TLV4 - число задаёт размер полей Tag и Length.
 */
public class TLV implements IBinable
{
	public int tag;
	public Binary value;
	public String description;

	// -----------------------------------------------------------------------------------------------------------------
	public TLV()
	{
		tag = 0;
		value = new Binary();
		description = "";
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * value НЕ клонируется, копируется ссылка.
	 */
	public TLV( int tag, Binary value )
	{
		this.tag = tag;
		this.value = value;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * value НЕ клонируется, копируется ссылка.
	 */
	public TLV( int tag, Binary value, String description )
	{
		this.tag = tag;
		this.value = value;
		this.description = description;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void toBin( Binary res )
	{
		BinBuilder bb = new BinBuilder( res );
		bb.append( tag );
		bb.append( value );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public TLV fromBin( final Binary bin, int offset )
	{
		BinParser parser = new BinParser( bin, offset );
		tag = parser.getInt();
		value = parser.getBinary();
		return this;
	}

	// =================================================================================================================
	/**
	 * Сформировать TLV4-запись в виде массива байт.
	 * @param tag - Тег.
	 * @param value - Поле Value.
	 * @return TLV4-запись.
	 */
	public static Binary TLV4( int tag, final Binary value )
	{
		Binary res = new Binary().reserve( 8 + value.size() );
		res.addInt( tag );
		res.addInt( value.size() );
		res.add( value );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сформировать TLV4-запись в виде массива байт.
	 * @param tag - Тег.
	 * @param value - несколько Binary для поля Value (конкатенируются).
	 * @return TLV4-запись.
	 */
	public static Binary TLV4( int tag, final Binary... value )
	{
		Binary res = new Binary().reserve( 50 );
		Binary val = Bin( value );
		res.addInt( tag );
		res.addInt( val.size() );
		res.add( val );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить список TLV4-записей в массив.
	 */
	public static Arr<TLV> parseTlv4Arr( final Binary bin )
	{
		Arr<TLV> arr = new Arr<TLV>();

		int size = bin.size();
		int offset = 0;
		while( offset < size )
		{
			MUST( (offset + 4 + 4) <= size, "Incorrect TLV4 List" );
			int tag = bin.getIntBE( offset );
			offset += 4;
			int len = bin.getIntBE( offset );
			offset += 4;

			MUST( (len >= 0) && (offset + len) <= size, "Incorrect LV4 List" );
			arr.add( new TLV( tag, new Binary( bin.getDataRef(), offset, len ) ) );
			offset += len;
		}

		return arr;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить список TLV4-записей в Map.
	 */
	public static Map<Integer, Binary> parseTlv4Map( final Binary bin )
	{
		Map<Integer, Binary> map = new LinkedHashMap<Integer, Binary>();

		int size = bin.size();
		int offset = 0;
		while( offset < size )
		{
			MUST( (offset + 4 + 4) <= size, "Incorrect TLV4 List" );
			int tag = bin.getIntBE( offset );
			offset += 4;
			int len = bin.getIntBE( offset );
			offset += 4;

			MUST( (len >= 0) && (offset + len) <= size, "Incorrect TLV4 List" );
			map.put( tag, new Binary( bin.getDataRef(), offset, len ) );
			offset += len;
		}

		return map;
	}
}