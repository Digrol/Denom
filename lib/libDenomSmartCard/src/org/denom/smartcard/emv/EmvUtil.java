// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv;

import java.util.*;
import org.denom.*;
import org.denom.format.*;
import org.denom.smartcard.ApduIso;
import org.denom.smartcard.CardReader;

import static org.denom.Binary.*;
import static org.denom.Ex.MUST;

/**
 * Utilities for EMV-based apps.
 */
public final class EmvUtil
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * EMV 4.3, Book 3, 6.5.12.
	 * @param pin - PIN в открытом виде, строка длиной 4..12 символов. Каждый символ - цифра.
	 * @param formatId - Формат 1 или 2 - первый нибл, идентификатор формата по ISO 9564-1 (default = 2).
	 * @return 8 байт, в формате 'CN' 'PP' 'PP' 'P/F P/F' 'P/F P/F' 'P/F P/F' 'P/F P/F' 'FF'
	 */
	public static Binary formatPin( String pin, int formatId )
	{
		int size = pin.length();
		MUST( (size >= 4) && (size <= 12), "Size of PIN must be 4-12 symbols" );

		Binary b = Bin().reserve( 8 );
		b.add( (formatId << 4) | size ); // 1-st byte
		b.add( Strings.PadRight( pin, 14, 'F' ) );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать с карты объекты данных из записей, указанных в AFL.<br>
	 * Тег 70 отбрасывается, содержимое каждой записи парсится как список TLV и помещается в Map в виде [Tag - Value].
	 * @param afl - поле Value тега TagEmv.AFL (берётся из ответа на команду GET PROCESSING OPTIONS)
	 * @param data - сюда будут добавлены объекты данных
	 * @param cmdRunner
	 * @return Конкатенация записей, участвующих в SDA.
	 */
	public static Binary readAflDataObjects( final Binary afl, Map<Integer, Binary> data, CardReader cr )
	{
		Arr<Binary> sdaRecIds = new Arr<Binary>();
		Map<Binary, Binary> records = readAflRecords( cr, parseAFL( afl, sdaRecIds ) );
		Binary sdaRecords = getSdaRecords( records, sdaRecIds );

		for( Binary value : records.values() )
		{
			BerTLV tlv = new BerTLV( value );
			BerTLVList tlvs = new BerTLVList( tlv.value );
			for( BerTLV rec : tlvs.recs )
			{
				data.put( rec.tag, rec.value );
			}
		}

		return sdaRecords;
	}

	// -----------------------------------------------------------------------------------------------------------------
	 /**
	  * Распарсить AFL.
	  * Элементы возвращаемых списков - 2 байта, идентифицирующие одну запись:
	  *   SFI (0-й байт) | recId (1-й байт).
	  * @param afl - поле Value тега TagEmv.AFL (из ответа на GET PROCESSING OPTIONS или параметр персонализации).
	  * @param sdaRecords - Может быть null. Список идентификаторов записей, из которых формируется SDA.
	  * @return Список идентификаторов записей, перечисленных в AFL.
	  */
	public static Arr<Binary> parseAFL( final Binary afl, Arr<Binary> sdaRecords )
	{
		final String ERR_MESSAGE = "Wrong AFL format";

		if( sdaRecords != null )
		{
			sdaRecords.clear();
		}

		MUST( (afl.size() & 0x03) == 0, ERR_MESSAGE ); // Размер кратен 4
		Arr<Binary> recIds = new Arr<>();
		
		// EMV 4.3, Book 3, 10.2 - Read Application Data
		// Каждые 4 байта задают диапазон записей одного RF-файла,
		// последний из 4-х байт - количество записей из этого диапазона, участвующих в SDA.
		for( int i = 0; i < afl.size(); i += 4 )
		{
			
			int sfiShifted = afl.get( i );     // 1-й байт - SFI, смещённый на 3 бита влево.
			int sfi = sfiShifted >>> 3;
			MUST( ((sfiShifted & 0x07) == 0) && (sfi > 0) && (sfi < 31), ERR_MESSAGE );

			int firstRec   = afl.get( i + 1 ); // 2-й байт - ID первой записи.
			int lastRec    = afl.get( i + 2 ); // 3-й байт - ID последней записи.
			int recsInSda  = afl.get( i + 3 ); // 4-й байт - Сколько записей из диапазона участвует в SDA.
			MUST( (firstRec != 0) && (lastRec >= firstRec) && (recsInSda <= (lastRec - firstRec + 1)), ERR_MESSAGE );

			for( int recNum = firstRec; recNum <= lastRec; ++recNum )
			{
				Binary recId = Bin( 2 );
				recId.set( 0, sfi );
				recId.set( 1, recNum );
				recIds.add( recId );
				
				if( (recsInSda > 0) && (sdaRecords != null) )
				{
					sdaRecords.add( recId );
					--recsInSda;
				}
			}
		}

		return recIds;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать с карты записи, указанные в AFL.<br>
	 * Содержимое записей помещается в Map в виде [recID - recordValue];
	 * recID [2 байта]: sfi | recNum.
	 * @param afl - поле Value тега TagEmv.AFL (берётся из ответа на команду GET PROCESSING OPTIONS)
	 * @return Считанные записи. Ключ - идентификатор записи (sfi | recNum).
	 */
	public static Map<Binary, Binary> readAflRecords( CardReader cr, Arr<Binary> recIds )
	{
		Map<Binary, Binary> records = new TreeMap<>();
		for( Binary recId : recIds )
		{
			cr.Cmd( ApduIso.ReadRecord( recId.get( 0 ), recId.get( 1 ) ) );
			records.put( recId, cr.resp );
		}
		return records;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сконкатенировать записи, участвующие в SDA.
	 */
	public static Binary getSdaRecords( Map<Binary, Binary> records, Arr<Binary> sdaRecIds )
	{
		Binary sdaRecords = Bin();
		for( Binary sdaRecId : sdaRecIds )
		{
			Binary record = records.get( sdaRecId );

			// EMV 4.3, Book 3, 10.3 - Offline Data Authentication.
			// Все записи, участвующие в SDA, должны быть в теге 0x70.
			BerTLV rec = new BerTLV( record );
			MUST( rec.tag == TagEmv.ReadRecordResponseMessageTemplate, "Record body for SDA must be in tag 0x70" );

			int sfi = sdaRecId.get( 0 );
			if( sfi < 11 )
			{
				// тег 0x70 отбрасывается, берётся только Value.
				sdaRecords.add( rec.value );
			}
			else
			{
				sdaRecords.add( record );
			}
		}
		return sdaRecords;
	}


// 	-----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить бинарную строку - конкатенацию значений для указанных тегов.<br>
	 * Данные ищутся в data. Если данные для тега не найдены, то они будут заданы нулями.
	 * @param dol - Data Object List = список TL (PDOL, CDOL1, CDOL2, DDOL, TDOL),
	 * поле Value для соответствующих тегов.
	 * @param data - Пары Tag - Value
	 * @return Конкатенация запрошенных значений
	 */
	public static Binary FormDOLRelatedData( final Binary dol, final Map<Integer, Binary> data )
	{
		Binary res = Bin();
		Int offset = new Int( 0 );

		while( offset.val < dol.size() )
		{
			Int Tag = new Int( 0 );
			MUST( BerTLV.parseTag( dol, offset, Tag ), "Wrong Tag in DOL" );
			Int Len = new Int( 0 );
			MUST( BerTLV.parseLength( dol, offset, Len ), "Wrong Length in DOL" );

			Binary val = getBinSafe( Tag.val, data );
			if( val.empty() )
			{	// Нет в списке, создаём нулевое значение.
				res.add( Bin( Len.val ) );
				continue;
			}

			MUST( val.size() == Len.val, "Incorrect data len for DOL request" );
			res.add( val );
		}

		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверка формата (n 12) суммы или лимита.
	 */
	public static boolean IsAmountNumeric( final Binary amount )
	{
		return (amount.size() == 6) && amount.Hex().matches( "[0-9]+" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Високосный год?
	 */
	public static boolean IsLeapYear( int year )
	{
		return ((year % 400) == 0) || (((year % 4) == 0) && ((year % 100) != 0));
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверка даты транзакции. Формат: YYMMDD.
	 */
	public static boolean IsYYMMDD( final Binary date )
	{
		String dateStr = date.Hex();
		if( (dateStr.length() != 6) || !dateStr.matches( "[0-9]+" ) )
		{
			return false;
		}

		int year = Integer.parseInt( dateStr.substring( 0, 2 ) ) + 2000;
		int month = Integer.parseInt( dateStr.substring( 2, 4 ) );
		int day = Integer.parseInt( dateStr.substring( 4, 6 ) );

		int maxDay = 31;
		if( (month == 4) || (month == 6) || (month == 9) || (month == 11) )
		{
			maxDay = 30;
		}
		else if( month == 2 )
		{
			maxDay = IsLeapYear( year ) ? 29 : 28;
		}

		return (month > 0) && (month <= 12) && (day > 0) && (day <= maxDay);
	}

}
