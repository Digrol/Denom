// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.etsi;

import org.denom.*;
import org.denom.format.BerTLV;
import org.denom.smartcard.CApdu;

import static org.denom.Binary.Bin;
//import static org.denom.format.BerTLV.Tlv;
import static org.denom.Ex.*;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Формирование CApdu для команд, описанных в стандартах:
 * ETSI TS 102 221; ETSI TS 102 223.
 */
public class ApduEtsi
{
	// =================================================================================================================
	// Generic Commands
	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	// ETSI TS 102 221, 11.1.2.2, Table 11.8: Coding of P1 
	public final static int STATUS_P1_NoIndication   = 0x00;
	public final static int STATUS_P1_AppInitialized = 0x01;
	public final static int STATUS_P1_AppTermination = 0x02;
	// ETSI TS 102 221, 11.1.2.2, Table 11.9: Coding of P2 
	public final static int STATUS_P2_SelectAnswer   = 0x00;
	public final static int STATUS_P2_DFName         = 0x01;
	public final static int STATUS_P2_NoAnswer       = 0x0C;
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * ETSI TS 102 221, 11.1.2, STATUS.
	 * @param p1 - см. константы выше - STATUS_P1_*.
	 * @param p2 - см. константы выше - STATUS_P2_*.
	 */
	public static CApdu Status( int p1, int p2 )
	{
		CApdu ap = new CApdu( 0x80, 0xF2, p1, p2, Bin(), CApdu.MAX_NE, "{ETSI} STATUS" );
		ap.isTlvData = true;
		return ap;
	}

	// =================================================================================================================
	// CAT Commands
	// =================================================================================================================
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * ETSI TS 102 221, 11.2.1, TERMINAL PROFILE.
	 */
	public static CApdu TerminalProfile( final Binary dataField )
	{
		return new CApdu( 0x80, 0x10, 0x00, 0x00, dataField, 0, "{ETSI} TERMINAL PROFILE" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * ETSI TS 102 221, 11.2.2, ENVELOPE.
	 */
	public static CApdu Envelope( int eventTag, final Binary eventData )
	{
		return new CApdu( 0x80, 0xC2, 0x00, 0x00, BerTLV.Tlv( eventTag, eventData ), CApdu.MAX_NE, "{ETSI} ENVELOPE" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static CApdu Envelope( int eventTag, final CTLVList ctlvs )
	{
		return Envelope( eventTag, ctlvs.toBin() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * ETSI TS 102 221, 11.2.3, FETCH.
	 */
	public static CApdu Fetch( int lengthOfExpectedData )
	{
		MUST( lengthOfExpectedData <= CApdu.MAX_NE, "Fetch: 'lengthOfExpectedData' too large" );
		return new CApdu( 0x80, 0x12, 0x00, 0x00, Bin(), lengthOfExpectedData, "{ETSI} FETCH" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * ETSI TS 102 221, 11.2.4, TERMINAL RESPONSE.
	 */
	public static CApdu TerminalResponse( final Binary dataField )
	{
		return new CApdu( 0x80, 0x14, 0x00, 0x00, dataField, 0, "{ETSI} TERMINAL RESPONSE" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static CApdu TerminalResponse( final CTLVList ctlvs )
	{
		return TerminalResponse( ctlvs.toBin() );
	}

	// =================================================================================================================
	// Data Oriented Commands
	// =================================================================================================================

	// RETRIEVE DATA
	// SET DATA
}
