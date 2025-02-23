// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8.struct;

import org.denom.Binary;

import static org.denom.Binary.Bin;

/**
 * EMV Сontactless Book C-8, Kernel 8 Specification v1.1, Annex A, A.1.55 Error Indication.
 * Поле value [6 байт] для TLV с тегом 9F8204.
 * Kernel возвращает его через Discretionary Data.
 */
public class ErrorIndication
{
	// -----------------------------------------------------------------------------------------------------------------
	public final static int L1_OK                  = 0x00;
	public final static int L1_TIMEOUT_ERROR       = 0x01;
	public final static int L1_TRANSIMISSION_ERROR = 0x02;
	public final static int L1_PROTOCOL_ERROR      = 0x03;

	public int L1 = L1_OK;

	// -----------------------------------------------------------------------------------------------------------------
	public final static int L2_OK                  = 0b00000000; // 0x00
	public final static int L2_CARD_DATA_MISSING   = 0b00000001; // 0x01
	public final static int L2_STATUS_BYTES        = 0b00000011; // 0x03
	public final static int L2_PARSING_ERROR       = 0b00000100; // 0x04
	public final static int L2_CARD_DATA_ERROR     = 0b00000110; // 0x06
	public final static int L2_TERMINAL_DATA_ERROR = 0b00001111; // 0x0F
	public final static int L2_DECRYPTION_FAILED   = 0b00010000; // 0x10
	public final static int L2_IAD_MAC_FAILED      = 0b00010010; // 0x12
	public final static int L2_EDA_MAC_FAILED      = 0b00010011; // 0x13

	public int L2 = L2_OK;

	// -----------------------------------------------------------------------------------------------------------------
	public final static int L3_OK                       = 0x00;
	public final static int L3_TIMEOUT                  = 0x01;
	public final static int L3_TRANSACTION_DATA_MISSING = 0x03;

	public int L3 = L3_OK;

	// -----------------------------------------------------------------------------------------------------------------
	public int SW12 = 0; // [2 байта]

	/**
	 * MessageIdentifier.*
	 */
	public int msgOnError = MessageIdentifier.NA;

	// -----------------------------------------------------------------------------------------------------------------
	public Binary toBin()
	{
		Binary b = Bin();

		b.add( L1 );
		b.add( L2 );
		b.add( L3 );
		b.addU16( SW12 );
		b.add( msgOnError );

		return b;
	}
}
