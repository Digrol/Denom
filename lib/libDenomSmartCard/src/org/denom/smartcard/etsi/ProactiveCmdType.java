// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.etsi;

/**
 * Type of command.
 * ETSI TS 102 223, 9.4.
 * Второй байт в поле value CTLV 'Command details (tag = 0x01)', п. 8.6.
 */
public class ProactiveCmdType
{
	public static final int REFRESH             = 0x01;
	public static final int MORE_TIME           = 0x02;
	public static final int POLL_INTERVAL       = 0x03;
	public static final int POLLING_OFF         = 0x04;
	public static final int SET_UP_EVENT_LIST   = 0x05;

	public static final int SEND_SHORT_MESSAGE  = 0x13;

	public static final int PLAY_TONE           = 0x20;
	public static final int SET_UP_MENU         = 0x25;
	public static final int TIMER_MANAGEMENT    = 0x27;

	public static final int OPEN_CHANNEL        = 0x40;
	public static final int CLOSE_CHANNEL       = 0x41;
	public static final int RECEIVE_DATA        = 0x42;
	public static final int SEND_DATA           = 0x43;
	public static final int GET_CHANNEL_STATUS  = 0x44;

	// -----------------------------------------------------------------------------------------------------------------
	public static String toStr( int cmdType )
	{
		switch( cmdType )
		{
			case REFRESH            : return "REFRESH";
			case MORE_TIME          : return "MORE_TIME";
			case POLL_INTERVAL      : return "POLL_INTERVAL";
			case POLLING_OFF        : return "POLLING_OFF";
			case SET_UP_EVENT_LIST  : return "SET_UP_EVENT_LIST";

			case SEND_SHORT_MESSAGE : return "SEND_SHORT_MESSAGE";

			case PLAY_TONE          : return "PLAY_TONE";
			case SET_UP_MENU        : return "SET_UP_MENU";
			case TIMER_MANAGEMENT   : return "TIMER_MANAGEMENT";

			case OPEN_CHANNEL       : return "OPEN_CHANNEL";
			case CLOSE_CHANNEL      : return "CLOSE_CHANNEL";
			case RECEIVE_DATA       : return "RECEIVE_DATA";
			case SEND_DATA          : return "SEND_DATA";
			case GET_CHANNEL_STATUS : return "GET_CHANNEL_STATUS";
			default:
				return "";
		}
	}
}
