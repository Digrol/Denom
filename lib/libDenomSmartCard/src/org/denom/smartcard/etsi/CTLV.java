// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.etsi;

import org.denom.Binary;
import org.denom.Int;
import org.denom.format.BerTLV;

import static org.denom.Ex.MUST;

/**
 * Comprehension-TLV - ETSI 102 220, 7.1.1.
 */
public class CTLV implements Cloneable
{
	public int tag;
	public Binary val;

	// -----------------------------------------------------------------------------------------------------------------
	public CTLV()
	{
		tag = 0;
		val = new Binary();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public CTLV( int tag, Binary value )
	{
		MUST( Int.isU8( tag ), "Wrong Comprehension TLV tag" );
		this.tag = tag;
		this.val = value.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public CTLV clone()
	{
		return new CTLV( this.tag, this.val );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить Comprehension-TLV запись, сериализованную в массиве.
	 * @param bin - байтовый массив, содержащий Comprehension-TLV запись.
	 * @param offset - начинаем парсить с этого смещения и возвращаем смещение, по которому начинается следующая запись.
	 * @return null - если не удалось распарсить.
	 */
	public static CTLV parse( final Binary bin, Int offset )
	{
		Int offs = new Int( offset.val );

		Int tagParsed = new Int( 0 );
		if( !parseTag( bin, offs, tagParsed ) )
			return null;

		Int lenParsed = new Int( 0 );
		if( !BerTLV.parseLength( bin, offs, lenParsed ) )
			return null;

		if( (offs.val + lenParsed.val) > bin.size() )
			return null;

		CTLV rec = new CTLV();
		rec.tag = tagParsed.val;
		rec.val.assign( bin, offs.val, lenParsed.val );
		offset.val = offs.val + lenParsed.val;
		return rec;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static boolean parseTag( final Binary bin, Int offset, Int tag  )
	{
		int offs = offset.val;
		if( offs >= bin.size() )
			return false;

		int b1 = bin.get( offs++ );
		
		if( (b1 == 00) || (b1 == 0x80) || (b1 == 0xFF) )
			return false;

		if( b1 == 0x7F )
		{
			// Three-byte format
			if( (offs + 2) > bin.size() )
				return false;
			
			tag.val = (b1 << 16) | bin.getU16( offs );
			offs += 2;
		}
		else
		{
			// Single byte format
			tag.val = b1;
		}

		offset.val = offs;
		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Append serialized CTLV to byte array.
	 */
	public void toBin( Binary bin )
	{
		appendTlvTag( bin, tag );
		BerTLV.appendTlvLen( bin, val.size() );
		bin.add( val );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * serialize to byte array.
	 */
	public Binary toBin()
	{
		Binary res = new Binary().reserve( 5 + val.size() );
		toBin( res );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void appendTlvTag( Binary bin, int tag )
	{
		if( Int.isU8( tag ) )
		{
			bin.add( tag );
		}
		else
		{
			bin.addU24( tag );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean isCRFlag()
	{
		return isCRFlag( this.tag );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static boolean isCRFlag( int tag )
	{
		MUST( Int.isU8( tag ), "wrong Comprehension TLV tag" );
		return (tag & 0x80) != 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сбрасывает бит CR в теге.
	 */
	public static int resetCRFlag( int tag )
	{
		if( Int.isU8(tag) )
			return tag & 0x7F;
		MUST( Int.isU24( tag ) && ((tag & 0xFF0000) == 0x7F0000), "CTLV: incorrect tag" );
		
		return tag & 0x00FF7FFF;
	}
}
