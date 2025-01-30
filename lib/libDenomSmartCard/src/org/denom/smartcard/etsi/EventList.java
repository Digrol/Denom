// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.etsi;

import java.util.HashSet;

import org.denom.Binary;

import static org.denom.Ex.MUST;

/**
 * Список событий, на которые подписывается карта.
 * Это конкатенация байтов. В каждой байте - код одного события.
 * Этот список - это поле value для CTLV с тегом 0x19 (или 0x99), константа в CTagCAT.EVENT_LIST.
 * ETSI TS 102 223 V17.2.0 (2023-03), 8.25. EventList.
 */
public class EventList
{
	public HashSet<Integer> list = new HashSet<>();

	// -----------------------------------------------------------------------------------------------------------------
	public EventList() {}

	// -----------------------------------------------------------------------------------------------------------------
	public EventList( final Binary bin )
	{
		assign( bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param bin - может быть пустым.
	 */
	public void assign( final Binary bin )
	{
		list.clear();
		for( int i = 0; i < bin.size(); ++i )
		{
			int event = bin.get( i );
			MUST( list.add( event ), "Event list already contains event " + event );
		}
	}

	// =================================================================================================================
	// Коды событий и их текстовое описание
	// =================================================================================================================
	public final static int MT_CALL                         = 0x00;
	public final static int CALL_CONNECTED                  = 0x01;
	public final static int CALL_DISCONNECTED               = 0x02;
	public final static int LOCATION_STATUS                 = 0x03;
	public final static int USER_ACTIVITY                   = 0x04;
	public final static int IDLE_SCREE_AVAILABLE            = 0x05;
	public final static int CARD_READER_STATUS              = 0x06;
	public final static int LANGUAGE_SELECTION              = 0x07;
	public final static int BROWSER_TERMINATION             = 0x08;
	public final static int DATA_AVAILABLE                  = 0x09;
	public final static int CHANNEL_STATUS                  = 0x0A;
	public final static int ACCESS_TECHNOLOGY_CHANGE_SINGLE = 0x0B;
	public final static int DISPLAY_PARAMETERS_CHANGED      = 0x0C;
	public final static int LOCAL_CONNECTION                = 0x0D;
	public final static int NETWORK_SEARCH_MODE_CHANGE      = 0x0E;
	public final static int BROWSING_STATUS                 = 0x0F;
	public final static int FRAMES_INFORMATION_CHANGE       = 0x10;
	public final static int I_WLAN_ACCESS_STATUS            = 0x11;
	public final static int NETWORK_REJECTION               = 0x12;
	public final static int HCI_CONNECTIVITY_EVENT          = 0x13;
	public final static int ACCESS_TECHNOLOGY_CHANGE_MULTI  = 0x14;
	public final static int CSG_CELL_SELECTION              = 0x15;
	public final static int CONTACTLESS_STATE_REQUEST       = 0x16;
	public final static int IMS_REGISTRATION                = 0x17;
	public final static int IMS_INCOMING_DATA               = 0x18;
	public final static int PROFILE_CONTAINER               = 0x19;
	// Void                                                 = 0x1A;
	public final static int SECURED_PROFILE_CONTAINER       = 0x1B;
	public final static int POLL_INTERVAL_NEGOTIATION       = 0x1C;
	public final static int DATA_CONNECTION_STATUS_CHANGE   = 0x1D;
	public final static int CAG_CELL_SELECTION              = 0x1E;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Текстовое описание event-а, либо пустая строка, если код события не известен.
	 */
	public static String getDescription( int event )
	{
		switch( event )
		{
			case MT_CALL:                         return "MT call";
			case CALL_CONNECTED:                  return "Call connected";
			case CALL_DISCONNECTED:               return "Call disconnected";
			case LOCATION_STATUS:                 return "Location status";
			case USER_ACTIVITY:                   return "User activity";
			case IDLE_SCREE_AVAILABLE:            return "Idle screen available";
			case CARD_READER_STATUS:              return "Card reader status";
			case LANGUAGE_SELECTION:              return "Language selection";
			case BROWSER_TERMINATION:             return "Browser termination";
			case DATA_AVAILABLE:                  return "Data available";
			case CHANNEL_STATUS:                  return "Channel status";
			case ACCESS_TECHNOLOGY_CHANGE_SINGLE: return "Access Technology Change (single access technology)";
			case DISPLAY_PARAMETERS_CHANGED:      return "Display parameters changed";
			case LOCAL_CONNECTION:                return "Local connection";
			case NETWORK_SEARCH_MODE_CHANGE:      return "Network Search Mode Chang";
			case BROWSING_STATUS:                 return "Browsing status";
			case FRAMES_INFORMATION_CHANGE:       return "Frames Information Change";
			case I_WLAN_ACCESS_STATUS:            return "I-WLAN Access Status";
			case NETWORK_REJECTION:               return "Network Rejection";
			case HCI_CONNECTIVITY_EVENT:          return "HCI connectivity event";
			case ACCESS_TECHNOLOGY_CHANGE_MULTI:  return "Access Technology Change (multiple access technologies)";
			case CSG_CELL_SELECTION:              return "CSG cell selection";
			case CONTACTLESS_STATE_REQUEST:       return "Contactless state request";
			case IMS_REGISTRATION:                return "IMS Registration";
			case IMS_INCOMING_DATA:               return "IMS Incoming data";
			case PROFILE_CONTAINER:               return "Profile Container";
			case SECURED_PROFILE_CONTAINER:       return "Secured Profile Container";
			case POLL_INTERVAL_NEGOTIATION:       return "Poll Interval Negotiation";
			case DATA_CONNECTION_STATUS_CHANGE:   return "Data Connection Status Change";
			case CAG_CELL_SELECTION:              return "CAG cell selection";
			default:
				return "";
		}
	}

}
