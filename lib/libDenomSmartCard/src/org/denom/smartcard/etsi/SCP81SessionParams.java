// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.etsi;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.denom.Binary;
import org.denom.format.JSONObject;

import static org.denom.Binary.*;
import static org.denom.Ex.*;
import static org.denom.format.LV.LV1;
import static org.denom.format.BerTLV.Tlv;

/**
 * Параметры сессии SCP81
 */
public class SCP81SessionParams
{
	// Connection params
	public String host; // "127.0.0.1"
	public int port; // 5555;
	public String networkAccessName = "internet";
	public int bufferSize = 512;

	// Security params
	public String PSKIdentity; // some string - "F0FFFFFFFFFFFFFFFFFF";
	public int keyVersion; // 0x40;
	public int keyIdentifier; // 0x01;

	// Retry Policy params
	public int retryCounter; // 3;
	public String retryWaitingDelay; // HH MM SS (normal nibbles);  "00 00 03" = 3 sec

	// HTTP POST params
	public String administrationHost; // "localhost"
	public String administrationURI; // "/scripts/testRFM"
	public String agentID; // "GETDATAEXT"

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать в массив байт для передачи в карту в теле СМС.
	 */
	public Binary toBin()
	{
		// Connection params
		Binary hostBin = Bin();
		try {
			hostBin.assign( InetAddress.getByName(host).getAddress() );
		} catch (UnknownHostException e) {
			THROW( "Wrong hostname: " + host );
		}

		CTLVList ctlvs = new CTLVList();
		ctlvs.add( CTagCAT.BEARER_DESCRIPTION, "03" ); // 03 = default bearer for requested transport layer
		ctlvs.add( CTagCAT.BUFFER_SIZE, Num_Bin( bufferSize, 2 ) );
		ctlvs.add( CTagCAT.NETWORK_ACCESS_NAME, LV1( Bin().fromUTF8( networkAccessName ) ) );
		ctlvs.add( CTagCAT.TRANSPORT_LEVEL, Bin().add("02").add( Num_Bin( port, 2 ) ) ); // '02': TCP, UICC in client mode, remote connection
		ctlvs.add( CTagCAT.OTHER_ADDRESS, Bin().add("21").add( hostBin ) ); // '21' = Ipv4 address
		Binary connectionParams = Tlv( 0x84, ctlvs.toBin() );

		// Security params
		Binary securityParams =
			Tlv( 0x85, Bin(
				LV1( Bin().fromUTF8( PSKIdentity ) ),
				Bin("02").add( keyVersion ).add( keyIdentifier ) ) );

		Binary retryPolicyParams = Tlv( 0x86, Bin()
				.addU16( retryCounter )
				.add( new CTLV( CTagCAT.TIMER_VALUE, Bin(retryWaitingDelay).nibbleSwap() ).toBin() ) );

		// HTTP POST params
		Binary httpParams =
			Tlv( 0x89, Bin(
				Tlv( 0x8A, Bin().fromUTF8( administrationHost ) ),
				Tlv( 0x8B, Bin().fromUTF8( agentID ) ),
				Tlv( 0x8C, Bin().fromUTF8( administrationURI ) )
			) );

		return Tlv( 0x81, Tlv(0x83, Bin( connectionParams, securityParams, retryPolicyParams, httpParams ) ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать все параметры из JSON.
	 */
	public void fromJSON( JSONObject jo )
	{
		// Connection parameters, тег "81/83/84"
		JSONObject joConnectionParams = jo.optJSONObject( "Connection Parameters" );
		if( joConnectionParams != null )
		{
			host = joConnectionParams.getString( "Host" );
			port = joConnectionParams.getInt( "Port" );
			bufferSize = joConnectionParams.getInt( "Buffer Size" );
		}

		// Security Parameters, тег "81/83/85"
		JSONObject joSecurityParams = jo.optJSONObject( "Security Parameters" );
		if( joSecurityParams != null )
		{
			PSKIdentity = joSecurityParams.getString( "PSK Identity" );
			Binary b = joSecurityParams.getBinary( "Key Version", 1 );
			keyVersion = b.get( 0 );
			b = joSecurityParams.getBinary( "Key Identifier", 1 );
			keyIdentifier = b.get( 0 );
		}

		// Retry Policy parameters, тег "81/83/86"
		JSONObject joRetryPolicyParams = jo.optJSONObject( "Retry Policy" );
		if( joRetryPolicyParams != null )
		{
			retryCounter = joRetryPolicyParams.getInt( "Retry Counter" );
			Binary b = joRetryPolicyParams.getBinary( "Retry Waiting Delay", 3 );
			retryWaitingDelay = b.Hex();
		}

		// HTTP POST parameters, тег "81/83/89"
		JSONObject joHTTPParams = jo.optJSONObject( "HTTP POST Parameters" );
		if( joHTTPParams != null )
		{
			// Тег "81/83/89/8A"
			administrationHost = joHTTPParams.optString( "Administration Host", null );
			// Тег "81/83/89/8B"
			agentID = joHTTPParams.optString( "Agent ID", null );
			// Тег "81/83/89/8C"
			administrationURI = joHTTPParams.optString( "Administration URI", null );
		}
	}
}
