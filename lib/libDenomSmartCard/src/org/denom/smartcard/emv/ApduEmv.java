// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv;

import org.denom.Binary;
import org.denom.Int;
import org.denom.format.BerTLV;
import org.denom.smartcard.CApdu;
import org.denom.smartcard.CpsDataGroup;

import static org.denom.Ex.MUST;

/**
 * Формирование CApdu для команд по спецификациям EMVCo.
 */
public class ApduEmv
{
	// Функции для следующих команд реализованы в ApduIso:
	// SELECT         -- EMV 4.3, Book 1, 11.3;   ISO 7816-4, 7.1.1.
	// READ RECORD    -- EMV 4.3, Book 3, 6.5.11; ISO 7816-4, 7.3.3.
	// GET CHALLENGE  -- EMV 4.3, Book 3, 6.5.6;  ISO 7816-4, 7.5.3.

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Команда STORE DATA для персонализации приложений согласно спецификации EMV CPS v1.1, 2007, 3.2.7
	 * @param dgi - идентификатор группы данных (2 байта)
	 * @param dgiData - данные группы.
	 * @param sequenceNumber - порядковый номер команды STORE DATA.
	 * @param needEncryption - если true, то указываем, что задаём режим "All DGIs encrypted under SKUdek".
	 * @param isLastCmd - последняя команда STORE DATA или нет.
	 */
	public static CApdu StoreData( int dgi, final Binary dgiData, int sequenceNumber, boolean needEncryption, boolean isLastCmd )
	{
		MUST( Int.isU16( dgi ), "DGI must be U16" );
		MUST( Int.isU8( sequenceNumber ), "sequenceNumber must be U8" );

		int p1 = 0; // noEncryption 
		if( needEncryption )
			p1 |= 0x60; // All DGIs encrypted under SKUdek

		if( isLastCmd )
			p1 |= 0x80; // last

		Binary dataField = new Binary().reserve( dgiData.size() + 5 );
		dataField.addU16( dgi );

		if( dgiData.size() < 255 )
		{
			dataField.add( dgiData.size() );
		}
		else
		{
			dataField.add( 0xFF );
			dataField.addU16( dgiData.size() );
		}

		dataField.add( dgiData );

		return new CApdu( 0x80, 0xE2, p1, sequenceNumber, dataField, 0, "{EMV CPS} STORE DATA" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static CApdu StoreData( final CpsDataGroup dg, int sequenceNumber, boolean isLastCmd )
	{
		return StoreData( dg.dgi, dg.data, sequenceNumber, dg.needEncryption, isLastCmd );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Команда GET PROCESSING OPTIONS -- EMV 4.4, Book 3, 6.5.8.<br>
	 * Карта возвращает AIP и AFL, а также другие данные (если ответ в format 2).
	 */
	public static CApdu GetProcessingOptions( final Binary pdolValues )
	{
		return new CApdu( 0x80, 0xA8, 0x00, 0x00, BerTLV.Tlv( TagEmv.CommandTemplate, pdolValues ), CApdu.MAX_NE,
			"{EMV} GET PROCESSING OPTIONS" );
	}

}
