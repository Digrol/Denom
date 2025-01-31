// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8;

/**
 * EMV Сontactless Book C-8, Kernel 8 Specification v1.1, Annex A, A.1.97 Next Cmd.
 */
public class NextCmd
{
	public final static int ReadRecord = 0x00;
	public final static int ReadData   = 0x01;
	public final static int None       = 0x02;
}
