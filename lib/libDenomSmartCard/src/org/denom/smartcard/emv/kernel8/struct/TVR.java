// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8.struct;

/**
 * EMV Сontactless Book C-8, Kernel 8 Specification v1.1, Annex A, A.1.131  Terminal Verification Results.
 */
public class TVR
{
	// Byte 1
	public static final long LocalAuthenticationWasNotPerformed     = 0x80_00_00_00_00L;
	public static final long LocalAuthenticationFailed              = 0x04_00_00_00_00L;

	// Byte 2
	public static final long DifferentApplicationVersions           = 0x00_80_00_00_00L;
	public static final long ExpiredApplication                     = 0x00_40_00_00_00L;
	public static final long ApplicationNotYetEffective             = 0x00_20_00_00_00L;
	public static final long RequestedServiceNotAllowed             = 0x00_10_00_00_00L;

	// Byte 3
	public static final long CardholderVerificationWasNotSuccessful = 0x00_00_80_00_00L;
	public static final long OnlineCVMCaptured                      = 0x00_00_04_00_00L;

	// Byte 4
	public static final long TransactionExceedsFloorLimit           = 0x00_00_00_80_00L;

	// Byte 5
	public static final long Kernel8ProcessingAndTVRFormat          = 0x00_00_00_00_80L;
	public static final long AIDMismatch                            = 0x00_00_00_00_40L;
	public static final long RRThresholdExceeded                    = 0x00_00_00_00_08L;
	public static final long RRTimeLimitsExceeded                   = 0x00_00_00_00_04L;
	public static final long RRPPerformed                           = 0x00_00_00_00_02L;
	public static final long RRPNotPerformed                        = 0x00_00_00_00_01L;
}
