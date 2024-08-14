// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.etsi;

/**
 * COMPREHENSION-TLV tags.
 * ETSI TS 102 220, 7.2, Table 7.23. Card application toolkit data objects.
 */
public class CTagCAT
{
	public static final int COMMAND_DETAILS        = 0x01;
	public static final int COMMAND_DETAILS_CR     = 0x81;

	public static final int DEVICE_IDENTITY        = 0x02;
	public static final int DEVICE_IDENTITY_CR     = 0x82;

	public static final int RESULT                 = 0x03;
	public static final int RESULT_CR              = 0x83;

	public static final int DURATION               = 0x04;
	public static final int DURATION_CR            = 0x84;

	public static final int ALPHA_IDENTIFIER       = 0x05;
	public static final int ALPHA_IDENTIFIER_CR    = 0x85;

	public static final int ADDRESS                = 0x06;
	public static final int ADDRESS_CR             = 0x86;


	public static final int SMS_TPDU               = 0x0B;
	public static final int SMS_TPDU_CR            = 0x8B;


	public static final int EVENT_LIST             = 0x19;
	public static final int EVENT_LIST_CR          = 0x99;


	public static final int TIMER_IDENTIFIER       = 0x24;
	public static final int TIMER_IDENTIFIER_CR    = 0xA4;

	public static final int TIMER_VALUE            = 0x25;
	public static final int TIMER_VALUE_CR         = 0xA5;


	public static final int BEARER_DESCRIPTION     = 0x35;
	public static final int BEARER_DESCRIPTION_CR  = 0xB5;

	public static final int CHANNEL_DATA           = 0x36;
	public static final int CHANNEL_DATA_CR        = 0xB6;

	public static final int CHANNEL_DATA_LENGTH    = 0x37;
	public static final int CHANNEL_DATA_LENGTH_CR = 0xB7;

	public static final int CHANNEL_STATUS         = 0x38;
	public static final int CHANNEL_STATUS_CR      = 0xB8;

	public static final int BUFFER_SIZE            = 0x39;
	public static final int BUFFER_SIZE_CR         = 0xB9;

	public static final int TRANSPORT_LEVEL        = 0x3C;
	public static final int TRANSPORT_LEVEL_CR     = 0xBC;

	public static final int OTHER_ADDRESS          = 0x3E;
	public static final int OTHER_ADDRESS_CR       = 0xBE;

	public static final int NETWORK_ACCESS_NAME    = 0x47;
	public static final int NETWORK_ACCESS_NAME_CR = 0xC7;

	// -----------------------------------------------------------------------------------------------------------------
	public static String getDescription( int tag )
	{
		tag &= 0x7F;
		switch( tag )
		{
			case COMMAND_DETAILS:           return "Command Details";
			case DEVICE_IDENTITY:           return "Device identity";
			case RESULT:                    return "Result";
			case DURATION:                  return "Result";
			case ALPHA_IDENTIFIER:          return "Duration";
			case ADDRESS:                   return "Alpha identifier";

			case SMS_TPDU:                  return "SMS TPDU";
			case EVENT_LIST:                return "Event list";
			case TIMER_IDENTIFIER:          return "Timer identifier";
			case TIMER_VALUE:               return "Timer value";
			case BEARER_DESCRIPTION:        return "Bearer description";
			case CHANNEL_DATA:              return "Channel data";
			case CHANNEL_DATA_LENGTH:       return "Channel data length";
			case CHANNEL_STATUS:            return "Channel status";
			case BUFFER_SIZE:               return "Buffer size";
			case NETWORK_ACCESS_NAME:       return "Network Access Name";
			case TRANSPORT_LEVEL:           return "UICC/terminal interface transport level";
			case OTHER_ADDRESS:             return "Other address (data destination address)";

			default:
				return "";
		}
	}

}
