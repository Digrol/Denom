// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv;

import org.denom.Binary;

import static org.denom.Ex.MUST;

/**
 * Метод генерации сессионных ключей карты.
 */
public final class SKDerivationMethod
{
	/**
	 * По стандарту EMV.
	 */
	public static final int EMV = 0;

	/**
	 * Проприетарно по спецификации M/Chip.
	 */
	public static final int MCHIP = 1;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выяснить метод генерации сессионного ключа по IAD.
	 * @param iad - [18 байт] Issuer Application Data (EMV тег - 0x9F10).
	 */
	public static int GetSKDerivationMethod( final Binary iad )
	{
		MUST( (iad.size() >= 18) && (iad.size() <= 32), "Wrond IAD size" );
		int cvn = iad.get( 1 );
		return ((cvn & 0x06) == 0x00) ? SKDerivationMethod.MCHIP : SKDerivationMethod.EMV;
	}

}
