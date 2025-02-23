// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8.struct;

/**
 * EMV Сontactless Book C-8, Kernel 8 Specification v1.1, Annex A, A.1.92 Message Identifier.
 */
public class MessageIdentifier
{
	public static final int CardReadOK             = 0x17;
	public static final int TryAgain               = 0x21;
	public static final int Approved               = 0x03;
	public static final int Approved_Sign          = 0x1A;
	public static final int Declined               = 0x07;
	public static final int TryanotherInterface    = 0x18;
	public static final int Error_OtherCard        = 0x1C;
	public static final int InsertCard             = 0x1D;
	public static final int SeePhone               = 0x20;
	public static final int Authorising_PleaseWait = 0x1B;
	public static final int ClearDisplay           = 0x1E;
	public static final int NA                     = 0xFF;

	// -----------------------------------------------------------------------------------------------------------------
	public static String getTextEngl( int msgId )
	{
		switch( msgId )
		{
			case CardReadOK:             return "CARD READ OK";
			case TryAgain:               return "TRY AGAIN";
			case Approved:               return "APPROVED";
			case Approved_Sign:          return "APPROVED - SIGN";
			case Declined:               return "DECLINED";
			case TryanotherInterface:    return "TRY ANOTHER INTERFACE";
			case Error_OtherCard:        return "ERROR - OTHER CARD";
			case InsertCard:             return "INSERT CARD";
			case SeePhone:               return "SEE PHONE";
			case Authorising_PleaseWait: return "AUTHORISING – PLEASE WAIT";
			default:
				return "N/A";
		}
	}
}
