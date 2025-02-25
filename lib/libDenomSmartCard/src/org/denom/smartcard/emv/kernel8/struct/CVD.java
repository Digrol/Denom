// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8.struct;

/**
 * EMV Сontactless Book C-8, Kernel 8 Specification v1.1, Annex A, A.1.25 Cardholder Verification Decision.
 */
public class CVD
{
	public static final int NO_CVM     = 0x00;
	public static final int SIGNATURE  = 0x01;
	public static final int ONLINE_PIN = 0x02;
	public static final int CDCVM      = 0x03;
	public static final int NA         = 0x0F;
	public static final int CV_FAILED  = 0xFF;
}
