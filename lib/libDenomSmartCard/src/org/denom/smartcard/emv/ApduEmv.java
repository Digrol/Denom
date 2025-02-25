// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv;

import org.denom.Binary;
import org.denom.Int;
import org.denom.format.BerTLV;
import org.denom.smartcard.CApdu;
import org.denom.smartcard.CpsDataGroup;

import static org.denom.Ex.MUST;
import static org.denom.Binary.Bin;

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
	 * Команда GET PROCESSING OPTIONS -- EMV 4.4, Book 3, 6.5.8.
	 * Карта возвращает AIP и AFL, а также другие TLV объекты (если ответ в format 2).
	 */
	public static CApdu GetProcessingOptions( final Binary pdolValues )
	{
		CApdu ap = new CApdu( 0x80, 0xA8, 0x00, 0x00, BerTLV.Tlv( TagEmv.CommandTemplate, pdolValues ), CApdu.MAX_NE,
			"{EMV} GET PROCESSING OPTIONS" );
		ap.isTlvData = true;
		return ap;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Команда GENERATE APPLICATION CRYPTOGRAM -- EMV 4.3, Book 3, 6.5.5.
	 */
	public static CApdu GenerateAC( int cryptogramType, final Binary cdolRelData, boolean moreCommands )
	{
		int p2 = moreCommands ? 0x80 : 0x00;
		CApdu ap = new CApdu( 0x80, 0xAE, cryptogramType, p2, cdolRelData, CApdu.MAX_NE, "{EMV} GENERATE AC" );
		ap.isTlvData = true;
		return ap;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Команда READ DATA.  Kernel C-8, 5.5.
	 * Карта вернёт зашифрованные на сессионном ключе данные + MAC.
	 * @param tag - 0x9F8111 – 0x9F811A.
	 */
	public static CApdu ReadData( int tag )
	{
		return new CApdu( 0x84, 0x32, 0x00, 0x00, Bin().addU24( tag ), CApdu.MAX_NE, "{EMV} READ DATA" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Команда WRITE DATA.  Kernel C-8, 5.7.
	 * Карта вернёт MAC от Plain TLV.
	 * @param moreCommands - будут ли ещё команды в этой сессии.
	 */
	public static CApdu WriteData( Binary encryptedTLV, boolean moreCommands )
	{
		int p2 = moreCommands ? 0x80 : 0x00;
		return new CApdu( 0x84, 0x34, 0x00, p2, encryptedTLV, CApdu.MAX_NE, "{EMV} WRITE DATA" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Команда EXCHANGE RELAY RESISTANCE DATA.  Kernel C-8, 5.2.
	 * Карта в ответе возвращает TLV с тегом 0x80, в котором value 10 байт, конкатенация:
	 *   Device Relay Resistance Entropy [4 байта]
	 *     |  Min Time For Processing Relay Resistance APDU [2 байта]
	 *     |  Max Time For Processing Relay Resistance APDU [2 байта]
	 *     |  Device Estimated Transmission Time For Relay Resistance R-APDU [2 байта].
	 */
	public static CApdu ExchangeRelayResistanceData( final Binary terminalEntropy )
	{
		return new CApdu( 0x80, 0xEA, 0x00, 0x00, terminalEntropy, CApdu.MAX_NE, "{EMV} EXCHANGE RELAY RESISTANCE DATA" );
	}
}
