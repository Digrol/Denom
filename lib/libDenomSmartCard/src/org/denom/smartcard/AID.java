// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.Binary;

/**
 * Common and widely used RIDs and AIDs of card packages and applet instances.
 */
public class AID
{
	public static final String RID_VISA       = "A000000003";
	public static final String RID_MASTERCARD = "A000000004";
	public static final String RID_GP         = "A000000151";
	public static final String RID_CHINA_UPAY = "A000000333";
	public static final String RID_NSPK       = "A000000658";

	// =================================================================================================================
	public static final Binary ISD_GLOBAL_PLATFORM   = new Binary( "A000000151000000" );
	public static final Binary ISD_VISA_OPENPLATFORM = new Binary( "A000000003000000" );
	public static final Binary ISD_MASTERCARD        = new Binary( "A000000004000000" );
	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	public static final String CHINA_UPAY_PACKAGE = "A00000033301";
	public static final String CHINA_UPAY_CLASS   = "A0000003330101";


	// -----------------------------------------------------------------------------------------------------------------
	public static final String MCHIP_PAYMENT   = "A000000004 1010";
	public static final String VISA_PAYMENT    = "A000000003 1010";
	public static final String CHINA_UPAY      = "A000000333 0101";
	public static final String NSPK_MIR        = "A000000658 1010";

	public static final String PSE             = "315041592E5359532E4444463031"; // 1PAY.SYS.DDF01
	public static final String PPSE            = "325041592E5359532E4444463031"; // 2PAY.SYS.DDF01

}