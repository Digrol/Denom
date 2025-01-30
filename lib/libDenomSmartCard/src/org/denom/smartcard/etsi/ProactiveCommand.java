// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.etsi;

import org.denom.Binary;
import org.denom.format.BerTLV;

import static org.denom.Ex.MUST;

/**
 * Синтаксический разбор проактивной команды.
 */
public class ProactiveCommand
{
	/**
	 * Список Comprehension-TLV - поле value BER-TLV 0xD0 (PROACTIVE_COMMAND).
	 */
	public CTLVList ctlvs;

	public CTLV cmdDetails; // тег - 0x01 или 0x81 
	
	/**
	 * Три байта в CTLV cmdDetails
	 */
	public int commandNumber;
	public int typeOfCommand;
	public int commandQualifier;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param fetchedData - Данные, которые возвращает карта в ответ на команду FETCH.
	 * ETSI TS 102 223, Annex C: Structure of CAT communications.
	 */
	public ProactiveCommand( Binary fetchedData )
	{
		// Парсинг проактивной команды - общие CTLV, печать в лог.
		BerTLV tlv = new BerTLV( fetchedData );
		MUST( tlv.tag == TagCAT.PROACTIVE_COMMAND, "Wrong proactive command tag" );

		ctlvs = CTLVList.parse( tlv.value );

		// ETSI TS 102 223, 8.6 Command details
		cmdDetails = ctlvs.find( CTagCAT.COMMAND_DETAILS );
		MUST( cmdDetails.val.size() == 3, "Wrong CTLV in proactive command: Command Details" );
		commandNumber = cmdDetails.val.get( 0 );
		typeOfCommand = cmdDetails.val.get( 1 );
		commandQualifier = cmdDetails.val.get( 2 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Ищет ctlv в списке ctlvs. 
	 * @param ctag - тег.
	 * @return Найденная запись или null, если запись не найдена.
	 */
	public CTLV find( int ctag )
	{
		return ctlvs.find( ctag );
	}
}
