// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8.struct;

import org.denom.Binary;

import static org.denom.Binary.Bin;

/**
 * EMV Сontactless Book C-8, Kernel 8 Specification v1.1,
 * Annex A, A.1.143 User Interface Request Data 1;
 * Annex A, A.1.144 User Interface Request Data 2.
 */
public class UIRD
{
	/**
	 * См. константы в MessageIdentifier.*
	 */
	public int messageId = MessageIdentifier.NA;

	// -----------------------------------------------------------------------------------------------------------------
	public final static int STATUS_NOT_READY         = 0x00;
	public final static int STATUS_IDLE              = 0x01;
	public final static int STATUS_READY_TO_READ     = 0x02;
	public final static int STATUS_PROCESSING        = 0x03;
	public final static int STATUS_CARD_READ_SUCCESS = 0x04;
	public final static int STATUS_PROCESSING_ERROR  = 0x05;
	public final static int STATUS_NA                = 0xFF;

	/**
	 * STATUS_*
	 */
	public int status = STATUS_NA;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * [3 байта], Format: n 6.
	 */
	public Binary holdTime = Bin( 3 );

	/**
	 * [8 байт]
	 * Format: an (padded with hexadecimal zeroes if length of tag '5F2D' is less than 8 bytes).
	 */
	public Binary languagePref = Bin( 8 );

	// -----------------------------------------------------------------------------------------------------------------
	public Binary toBin()
	{
		Binary b = Bin();

		b.add( messageId );
		b.add( status );
		b.add( holdTime );
		b.add( languagePref );

		return b;
	}
}
