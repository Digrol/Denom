// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.etsi;

import java.util.Arrays;
import java.util.Locale;

import org.denom.*;

import static org.denom.Ex.MUST;

/**
 * Список Comprehension-TLV-записей.
 */
public class CTLVList
{
	public Arr<CTLV> recs = new Arr<>();

	// -----------------------------------------------------------------------------------------------------------------
	public CTLVList()
	{
		this.recs = new Arr<>();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public CTLVList( final String hex )
	{
		assign( new Binary( hex ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public CTLVList( final Binary bin )
	{
		assign( bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить байтовый массив как список (конкатенация) CTLV-записей.
	 */
	public CTLVList assign( final Binary bin )
	{
		return assign( bin, new Int(0) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить CTLV-запись в список.
	 */
	public void add( CTLV ctlv )
	{
		recs.add( ctlv.clone() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить CTLV-запись в список.
	 */
	public void add( int tag, String hexVal )
	{
		recs.add( new CTLV( tag, new Binary( hexVal ) ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить CTLV-запись в список.
	 */
	public void add( int tag, final Binary value )
	{
		recs.add( new CTLV( tag, value ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить список CTLV-запсией. Начиная с заданного смещения и до конца массива.
	 */
	public CTLVList assign( final Binary bin, Int offset )
	{
		recs.clear();
		while( offset.val < bin.size() )
		{
			CTLV rec = CTLV.parse( bin, offset );
			MUST( rec != null, "CTLV: cant parse array as CTLV list" );
			recs.add( rec );
		}
		MUST( offset.val == bin.size(), "Wrong CTLV list" );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить байтовый массив как список (конкатенация) CTLV-записей.
	 */
	public static CTLVList parse( final Binary bin )
	{
		return new CTLVList( bin );
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Найти в списке запись с заданным тегом tag.<br>
	 * В списке может быть несколько записей с тегом tag.
	 * @param tag - Тег записи (CR-flag игнорируется при поиске).
	 * @param nth - Какая по счёту запись нужна (считаем от 1).
	 * @return Искомая запись, или null, если запись не найдена.
	 */
	public CTLV find( int tag, int nth )
	{
		int k = 0;
		for( int i = 0; i < recs.size(); ++i )
		{
			if( CTLV.resetCRFlag( recs.get( i ).tag ) == CTLV.resetCRFlag( tag ) )
				if( ++k == nth )
					return recs.get( i );
		}
		return null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public CTLV find( int tag )
	{
		return find( tag, 1 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверяет, что в списке CTLV есть требуемый тег с требуемым значением.
	 */
	public void checkContains( int tag, String valueHex, String errorDecription )
	{
		CTLV ctlv = find( tag );
		MUST( (ctlv != null) && ctlv.val.equals( valueHex ), errorDecription );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать массив CTLV-записей в массив байт.
	 */
	public void toBin( Binary bin )
	{
		for( CTLV ctlv : recs )
			ctlv.toBin( bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary toBin()
	{
		Binary res = new Binary().reserve( recs.size() * 5 );
		toBin( res );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Представить список CTLV-записей в виде многострочного текста для вывода на печать.
	 * @param eachStringOffset - Сколько пробелов добавлять в начале каждой строки.
	 * @param withDescription - добавлять ли описание тегов, см. класс CTagCAT.
	 * @return
	 */
	public String toString( int eachStringOffset, boolean withDescription )
	{
		char[] offsetArr = new char[ eachStringOffset ];
		Arrays.fill( offsetArr, ' ' );

		StringBuilder res = new StringBuilder( 300 );

		Binary tagBin = new Binary();

		for( CTLV rec : recs )
		{
			res.append( offsetArr );

			res.append( ((rec.tag & 0x80) != 0) ? "CR " : "   " );
			tagBin.clear();
			CTLV.appendTlvTag( tagBin, rec.tag );
			res.append( tagBin.Hex() );

			res.append( String.format( Locale.US, " [ %3d ] :  ", rec.val.size() ) );

			res.append( rec.val.Hex() );

			if( withDescription )
			{
				String desc = CTagCAT.getDescription( rec.tag );
				if( !desc.isEmpty() )
					res.append( "  --  " + desc );
			}
			res.append( '\n' );
		}

		return res.toString();
	}
}
