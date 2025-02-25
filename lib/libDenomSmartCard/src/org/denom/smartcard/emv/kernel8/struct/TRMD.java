// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8.struct;

/**
 * EMV Сontactless Book C-8, Kernel 8 Specification v1.1, Annex A, A.1.129  Terminal Risk Management Data.
 */
public class TRMD
{
	// Byte 1
	public static final long EncipheredPINVerifiedOnlineContactless = 0x40_00_00_00_00_00_00_00L;
	public static final long SignatureContactless                   = 0x20_00_00_00_00_00_00_00L;
	public static final long NoCVMRequiredContactless               = 0x08_00_00_00_00_00_00_00L;
	public static final long CDCVMContactless                       = 0x04_00_00_00_00_00_00_00L;

	// Byte 2
	public static final long CVMLimitExceeded                       = 0x00_80_00_00_00_00_00_00L;
	public static final long EncipheredPINVerifiedOnlineContact     = 0x00_40_00_00_00_00_00_00L;
	public static final long SignatureContact                       = 0x00_20_00_00_00_00_00_00L;
	public static final long EncipheredPINVerificationByICCContact  = 0x00_10_00_00_00_00_00_00L;
	public static final long NoCVMRequiredContact                   = 0x00_08_00_00_00_00_00_00L;
	public static final long CDCVMContact                           = 0x00_04_00_00_00_00_00_00L;
	public static final long PlainPINVerificationByICCContact       = 0x00_02_00_00_00_00_00_00L;

	// Byte 3 RFU

	// Byte 4
	public static final long CDCVMBypassRequested                   = 0x00_00_00_80_00_00_00_00L;
	public static final long SCAExempt                              = 0x00_00_00_40_00_00_00_00L;

	// Byte 5-8 RFU
}
