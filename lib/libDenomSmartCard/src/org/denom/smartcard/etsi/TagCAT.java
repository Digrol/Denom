// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.etsi;

/**
 * BerTLV-теги из стандарта ETSI TS 102 220, 7.2.
 */
public class TagCAT
{
	// Table 7.17.  Card application toolkit templates.
	public static final int PROACTIVE_COMMAND               = 0xD0;
	public static final int SMS_PP_DOWNLOAD                 = 0xD1;
	public static final int CELL_BROADCAST_DOWNLOAD         = 0xD2;
	public static final int MENU_SELECTION                  = 0xD3;
	public static final int CALL_CONTROL                    = 0xD4;
	public static final int MO_SHORT_MESSAGE_CONTROL        = 0xD5;
	public static final int EVENT_DOWNLOAD                  = 0xD6;
	public static final int TIMER_EXPIRATION                = 0xD7;
	public static final int USSD_DOWNLOAD                   = 0xD9;
	public static final int MMS_TRANSFER_STATUS             = 0xDA;
	public static final int MMS_NOTIFICATION_DOWNLOAD       = 0xDB;
	public static final int TERMINAL_APPLICATION            = 0xDC;
	public static final int GEOGRAPHICAL_LOCATION_REPORTING = 0xDD;
	public static final int ENVELOPE_CONTAINER              = 0xDE;
	public static final int PRO_SE_REPORT                   = 0xDF;

	// Table 7.18.  Remote Management Application Data templates
	public static final int COMMAND_SCRIPTING_DEFINITE_LEN    = 0xAA;
	public static final int RESPONSE_SCRIPTING_DEFINITE_LEN   = 0xAB;
	public static final int COMMAND_SCRIPTING_INDEFINITE_LEN  = 0xAE;
	public static final int RESPONSE_SCRIPTING_INDEFINITE_LEN = 0xAF;

	// Table 7.19.  Command Scripting template ('AA' or 'AE').
	public static final int C_APDU            = 0x22;
	public static final int IMMEDIATE_ACTION  = 0x81;
	public static final int ERROR_ACTION      = 0x82;
	public static final int SCRIPT_CHAINING   = 0x83;

	// Table 7.20.  Response Scripting template ('AB' or 'AF').
	public static final int R_APDU = 0x23;
	public static final int NUMBER_OF_EXECUTED_C_APDU       = 0x80;
	public static final int NUMBER_OF_EXECUTED_COMMAND_TLVS = 0x80;
	public static final int IMMEDIATE_ACTION_RESPONSE       = 0x81;
	public static final int SCRIPT_CHAINING_RESPONSE        = 0x83;
	public static final int BAD_FORMAT                      = 0x90;
}
