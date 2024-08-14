// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.etsi;

import org.denom.Binary;
import org.denom.Strings;
import org.denom.crypt.*;
import org.denom.format.LV;

import static org.denom.Binary.*;

/**
 * SMS для запуска сессии SCP81.
 * SMS-DELIVER type. 123 040, 9.2.2.1.
 * 123 048, 6.2, Table 6.
 */
public class SCP80Sms
{
	public int firstByte = 0x60;
	public String originAddress; //Phone number "79165793369"
	public int TP_PID = 0x7F;
	public int TP_DCS = 0xF6;
	public String timeStamp; // YY MM DD HH mm SS TimeZone, for ex. "23 07 17  10 58 07  00"

	public Binary SPI; // "0A01"
	public Binary KIC; // "11"
	public Binary KID; // "11"
	public Binary TAR; // "B20100"
	public Binary Counter; // "00 00 00 00 01"
	public Binary PCNTR = Bin("00");

	public Binary keyOTAMac; // "0123456789ABCDEF 0123456789ABCDEF"

	// -----------------------------------------------------------------------------------------------------------------
	public static Binary encodePhoneNumber( int TON_NPI, String phoneNum )
	{
		int len = phoneNum.length();
		len = ((len & 0x01) == 1) ? (len + 1) : len;
		String destStr = Strings.PadRight( phoneNum,len, 'F' );
		Binary bin = Bin( Bin( 1, TON_NPI ), Bin( destStr ).nibbleSwap() ); // 91 = TON/NPI |  swap(phoneNumber)
		return bin;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static Binary calcCCS( final Binary data, final Binary des3Key )
	{
		Binary pad = Bin( (8 - data.size() % DES2_EDE.BLOCK_SIZE) % DES2_EDE.BLOCK_SIZE );
		Binary aligned = Bin( data, pad );
		DES2_EDE des = new DES2_EDE( des3Key );
		Binary ccs = des.calcCCS( aligned, AlignMode.NONE, CCSMode.FAST );
		return ccs;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary toBin( final Binary userData )
	{
		Binary sms = Bin().reserve( userData.size() + 40 );

		Binary binOriginAddr = Bin( Bin(1, originAddress.length()), encodePhoneNumber( 0x91, originAddress ) );

		sms.add( firstByte );
		sms.add( binOriginAddr );
		sms.add( TP_PID );
		sms.add( TP_DCS );
		sms.add( Bin( timeStamp ).nibbleSwap() );

		Binary cmdHeader = Bin( SPI, KIC, KID, TAR, Counter, PCNTR );
		int dsLen = 8;

		// 123 048, 6.2, Table 6.
		Binary lvCmdHeader = Bin().add( cmdHeader.size() + dsLen ).add( cmdHeader );
		Binary toSignPart1 = Bin().addU16( lvCmdHeader.size() + dsLen + userData.size() ).add( lvCmdHeader );

		Binary ccs = calcCCS( Bin( toSignPart1, userData ), keyOTAMac );

		Binary fullUserData = Bin( LV.LV1(Bin("70 00")) ).add( toSignPart1 ).add( ccs ).add( userData );
		sms.add( fullUserData.size() );
		sms.add( fullUserData );

		return sms;
	}
}
