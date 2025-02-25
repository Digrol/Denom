// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8.struct;

/**
 * EMV Сontactless Book C-8, Kernel 8 Specification v1.1, Annex A, A.1.34 ACType in Cryptogram Information Data
 */
public class ACType
{
	// Выделить два нужных бита из байта
	public static final int	MASK = 0xC0;

	public static final int AAC  = 0x00;
	public static final int TC   = 0x40;
	public static final int ARQC = 0x80;
}
