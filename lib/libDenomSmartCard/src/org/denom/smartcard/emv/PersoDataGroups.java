// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv;

import org.denom.Binary;
import org.denom.Int;
import org.denom.format.BerTLV;
import org.denom.smartcard.CpsDataGroup;

import static org.denom.Binary.Bin;
import static org.denom.Binary.Num_Bin;
import static org.denom.Ex.MUST;

/**
 * Статические методы для формирования Data Groups (DG) для персонализации EMV-приложений.
 */
public final class PersoDataGroups
{
	/**
	 * Группа данных: Одна запись (record) для RF-файла.
	 */
	public static CpsDataGroup DG_Record( int recordId, final Binary recordBody )
	{
		MUST( Int.isU16( recordId ), "recordId > 0xFFFF" );
		return new CpsDataGroup( recordId, recordBody, "DATA GROUP:  Record " + Num_Bin( recordId, 2 ).Hex() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Группа данных: Проприетарные данные (TLV: A5 L V) для ответа на SELECT (формирование FCI) по контактному интерфейсу.
	 */
	public static CpsDataGroup DG_9102_FciProprietaryTemplateContact( final Binary tlvA5 )
	{
		MUST( BerTLV.isTLV( tlvA5 ), "A5 is not TLV" );
		return new CpsDataGroup( 0x9102, tlvA5, "DATA GROUP:  FCI Proprietary Template. Tag A5 (contact)" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Группа данных: Проприетарные данные (TLV: A5 L V) для ответа на SELECT (формирование FCI) по бесконтактному интерфейсу.
	 */
	public static CpsDataGroup DG_9103_FciProprietaryTemplateContactless( final Binary tlvA5 )
	{
		MUST( BerTLV.isTLV( tlvA5 ), "A5 is not TLV" );
		return new CpsDataGroup( 0x9103, tlvA5, "DATA GROUP:  FCI Proprietary Template. Tag A5 (contactless)" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Группа данных: AIP и AFL в TLV-объектах (по контактному интерфейсу).
	 */
	public static CpsDataGroup DG_9104_AIP_AFL( final Binary aipValue, final Binary aflValue )
	{
		Binary tlvAIP = BerTLV.Tlv( TagEmv.AIP, aipValue );
		Binary tlvAFL = BerTLV.Tlv( TagEmv.AFL, aflValue );
		return new CpsDataGroup( 0x9104, Bin( tlvAIP, tlvAFL ), "DATA GROUP:  AIP and AFL (Contact)" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Группа данных: AIP и AFL в TLV-объектах (по бесконтактному интерфейсу).
	 */
	public static CpsDataGroup DG_B104_AIP_AFLContactless( final Binary aipValue, final Binary aflValue )
	{
		Binary tlvAIP = BerTLV.Tlv( TagEmv.AIP, aipValue );
		Binary tlvAFL = BerTLV.Tlv( TagEmv.AFL, aflValue );
		return new CpsDataGroup( 0xB104, Bin( tlvAIP, tlvAFL ), "DATA GROUP:  AIP and AFL (Contactless)" );
	}

}
