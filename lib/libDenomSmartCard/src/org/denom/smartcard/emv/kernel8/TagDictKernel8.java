// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8;

import java.util.HashMap;
import org.denom.smartcard.emv.ITagDictionary;
import org.denom.smartcard.emv.TagEmv;
import org.denom.smartcard.emv.TagInfo;

/**
 * Cловарь со списком тегов и информацией о них.
 * В этом словаре все теги из EMV Сontactless Book C-8, Kernel 8 Specification v1.1, Annex A. Data Dictionary.
 */
public class TagDictKernel8 implements ITagDictionary
{
	/**
	 * key: Tag
	 */
	public static HashMap<Integer, TagInfo> tags;

	/**
	 * key: Tag Name
	 */
	public static HashMap<String, TagInfo> tagsByName;

	// -----------------------------------------------------------------------------------------------------------------
	public TagDictKernel8()
	{
		initDict();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return null, если тега нет в словаре.
	 */
	@Override
	public TagInfo find( int tag )
	{
		return tags.get( tag );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return null, если тега нет в словаре.
	 */
	@Override
	public TagInfo find( String name )
	{
		return tagsByName.get( name );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void add( int tag, String name, int minLen, int maxLen, boolean fromCard )
	{
		TagInfo info = new TagInfo( tag, name, minLen, maxLen, fromCard );
		tags.put( tag, info );
		tagsByName.put( name, info );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void add( int tag, String name, int len, boolean fromCard )
	{
		TagInfo info = new TagInfo( tag, name, len, len, fromCard );
		tags.put( tag, info );
		tagsByName.put( name, info );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private synchronized static void initDict()
	{
		if( tags != null )
			return;

		tags = new HashMap<Integer, TagInfo>();
		tagsByName = new HashMap<String, TagInfo>();

		add( TagEmv.AccountType, // A.1.1
				"Account Type",
				1, false );

		add( TagEmv.AcquirerIdentifier, // A.1.2
				"Acquirer Identifier",
				6, false );

		add( TagEmv.AdditionalTerminalCapabilities, // A.1.5
				"Additional Terminal Capabilities",
				5, false );

		add( TagEmv.AmountAuthorisedNumeric, // A.1.6
				"Amount, Authorised (Numeric)",
				6, false );

		add( TagEmv.AmountOtherNumeric, // A.1.7
				"Amount, Other (Numeric)",
				6, false );

		add( TagEmv.ApplicationCryptogram, // A.1.8
				"Application Cryptogram",
				8, true );

		add( TagEmv.ApplicationCurrencyCode, // A.1.9
				"Application Currency Code",
				2, true );

		add( TagEmv.ApplicationCurrencyExponent, // A.1.10
				"Application Currency Exponent",
				1, true );

		add( TagEmv.ApplicationExpirationDate, // A.1.11
				"Application Expiration Date",
				3, true );

		add( TagEmv.AFL, // A.1.12
				"Application File Locator",
				248, true );

		add( TagEmv.ApplicationIdentifierTerminal, // A.1.13
				"Application Identifier (Configuration Data)",
				5, 16, false );

		add( TagEmv.AIP, // A.1.14
				"Application Interchange Profile",
				2, true );

		add( TagEmv.ApplicationLabel, // A.1.15
				"Application Label",
				0, 16, true );

		add( TagEmv.PAN, // A.1.16
				"Application PAN",
				1, 10, true );

		add( TagEmv.PAN_SN, // A.1.17
				"Application PAN Sequence Number",
				1, true );

		add( TagEmv.ApplicationPreferredName, // A.1.18
				"Application Preferred Name",
				0, 16, true );

		add( TagEmv.ApplicationPriorityIndicator, // A.1.19
				"Application Priority Indicator",
				1, true );

		add( TagEmv.ASRPD, // A.1.20
				"Application Selection Registered Proprietary Data",
				0, 255, true );

		add( TagEmv.ATC, // A.1.21
				"Application Transaction Counter",
				2, true );

		add( TagEmv.ApplicationUsageControl, // A.1.22
				"Application Usage Control",
				2, true );

		add( TagEmv.ApplicationVersionNumberTerminal, // A.1.23
				"Application Version Number (Reader)",
				2, false );

		add( TagKernel8.AuthenticatedApplicationData, // A.1.24
				"Authenticated Application Data",
				0, 128, true );

		add( TagKernel8.CardholderVerificationDecision, // A.1.25
				"Cardholder Verification Decision",
				1, true );

		add( TagKernel8.CardCapabilitiesInformation, // A.1.26
				"Card Capabilities Information",
				2, true );

		add( TagKernel8.CardDataInputCapability, // A.1.27
				"Card Data Input Capability",
				1, false );

		add( TagKernel8.CardKeyData, // A.1.28
				"Card Key Data",
				64, 132, true );

		add( TagKernel8.CardQualifier, // A.1.29
				"Card Qualifier",
				7, true );

		add( TagKernel8.CardTVR, // A.1.30
				"Card TVR",
				5, true );

		add( TagEmv.CDOL1, // A.1.31
				"CDOL1",
				0, 250, true );

		add( TagEmv.CAPublicKeyIndexICC, // A.1.33
				"Certification Authority Public Key Index (Card)",
				1, true );

		add( TagEmv.CryptogramInformationData, // A.1.34
				"Cryptogram Information Data",
				1, true );

		add( TagKernel8.CVMCapabilityCVMRequired, // A.1.37
				"CVM Capability - CVM Required",
				1, false );

		add( TagKernel8.CVMCapabilityNoCVMRequired, // A.1.38
				"CVM Capability – No CVM Required",
				1, false );

		add( TagEmv.CVMResults, // A.1.39
				"CVM Results",
				3, false );

		for( int i = 1; i <= 10; ++i )
			add( TagKernel8.DataEnvelopeX + i, // A.1.40
					"Data Envelope " + Integer.toString( i ),
					0, 243, true );

		add( TagKernel8.DataEnvelopesToWrite, // A.1.41
				"Data Envelopes To Write",
				0, 0xFFFF, false );

		add( TagKernel8.DataNeeded, // A.1.43
				"Data Needed",
				0, 0xFFFF, false );

		add( TagKernel8.DataRecord, // A.1.44
				"Data Record",
				0, 0xFFFF, false );

		add( TagKernel8.DataToSend, // A.1.45
				"Data To Send",
				0, 0xFFFF, false );

		add( TagKernel8.DefaultCDOL1, // A.1.46
				"Default CDOL1",
				0, 250, false );

		add( TagKernel8.DefaultIADMACOffset, // A.1.47
				"Default IAD MAC Offset",
				1, false );

		add( TagEmv.DFName, // A.1.50
				"DF Name",
				5, 16, true );

		add( TagKernel8.DiscretionaryDataTagList, // A.1.51
				"Discretionary Data Tag List",
				0, 0xFFFF, false );

		add( TagKernel8.DiscretionaryData, // A.1.52
				"Discretionary Data",
				0, 0xFFFF, false );

		add( TagKernel8.EDA_MAC, // A.1.54
				"Enhanced Data Authentication MAC",
				8, true );

		add( TagKernel8.ErrorIndication, // A.1.55
				"Error Indication",
				6, false );

		add( TagKernel8.ExtendedSDATagList, // A.1.56
				"Extended SDA Tag List",
				0, 255, true );

		add( TagEmv.FCI_IssuerDiscretionaryData, // A.1.58
				"File Control Information Issuer Discretionary Data",
				0, 220, true );

		add( TagEmv.FCI_ProprietaryTemplate, // A.1.59
				"File Control Information Proprietary Template",
				0, 240, true );

		add( TagEmv.FCI, // A.1.60
				"File Control Information Template",
				250, true );

		add( TagKernel8.HoldTimeValue, // A.1.62
				"Hold Time Value",
				1, false );

		add( TagKernel8.IAD_MACOffset, // A.1.63
				"IAD MAC Offset",
				1, true );

		add( TagKernel8.ICCECCPublicKey_RSACert, // A.1.64
				"ICC ECC Public Key (for RSA Certificates)",
				32, 66, true );

		add( TagEmv.ICC_PublicKeyCertificate, // A.1.65
				"ICC Public Key Certificate",
				0, 248, true );

		add( TagEmv.ICC_PublicKeyExponent, // A.1.66
				"ICC RSA Public Key Exponent",
				1, 3, true );

		add( TagEmv.ICC_PublicKeyRemainder, // A.1.67
				"ICC RSA Public Key Remainder",
				0, 255, true );

		add( TagEmv.InterfaceDeviceSerialNumber, // A.1.68
				"Interface Device Serial Number",
				8, false );

		add( TagEmv.IssuerApplicationData, // A.1.69
				"Issuer Application Data",
				0, 32, true );

		add( TagKernel8.IAD_MAC, // A.1.70
				"Issuer Application Data MAC",
				8, false );

		add( TagEmv.IssuerCodeTableIndex, // A.1.71
				"Issuer Code Table Index",
				1, true );

		add( TagEmv.IIN, // A.1.72
				"Issuer Identification Number",
				3, true );

		add( TagEmv.IINE, // A.1.73
				"Issuer Identification Number Extended",
				3, 4, true );

		add( TagEmv.IssuerPublicKeyCertificate, // A.1.74
				"Issuer Public Key Certificate",
				0, 248, true );

		add( TagEmv.IssuerPublicKeyExponent, // A.1.75
				"Issuer RSA Public Key Exponent",
				1, 3, true );

		add( TagEmv.IssuerPublicKeyRemainder, // A.1.76
				"Issuer RSA Public Key Remainder",
				0, 255, true );

		add( TagKernel8.KernelConfiguration, // A.1.77
				"Kernel Configuration",
				2, false );

		add( TagKernel8.KernelKeyData, // A.1.79
				"Kernel Key Data",
				0, 132, false );

		add( TagKernel8.KernelQualifier, // A.1.80
				"Kernel Qualifier",
				8, false );

		add( TagKernel8.KernelReservedTVRMask, // A.1.81
				"Kernel Reserved TVR Mask",
				5, false );

		add( TagEmv.LanguagePreference, // A.1.82
				"Language Preference",
				2, 8, true );

		add( TagEmv.LogEntry, // A.1.84
				"Log Entry",
				2, true );

		add( TagKernel8.MaximumRelayResistanceGracePeriod, // A.1.85
				"Maximum Relay Resistance Grace Period",
				2, false );

		add( TagEmv.MerchantCategoryCode, // A.1.88
				"Merchant Category Code",
				2, false );

		add( TagEmv.MerchantIdentifier, // A.1.89
				"Merchant Identifier",
				15, false );

		add( TagEmv.MerchantNameAndLocation, // A.1.90
				"Merchant Name and Location",
				0, 0xFFFF, false );

		add( TagKernel8.MessageHoldTime, // A.1.91
				"Message Hold Time",
				3, false );

		add( TagKernel8.MessageIdentifiersOnRestart, // A.1.93
				"Message Identifiers On Restart",
				0, 32, false );

		add( TagKernel8.MinimumRelayResistanceGracePeriod, // A.1.95
				"Minimum Relay Resistance Grace Period",
				2, false );

		add( TagKernel8.OutcomeParameterSet, // A.1.98
				"Outcome Parameter Set",
				8, false );

		add( TagEmv.PAR, // A.1.99
				"Payment Account Reference",
				29, true );

		add( TagEmv.PDOL, // A.1.100
				"PDOL",
				0, 240, true );

		add( TagKernel8.ProceedToFirstWriteFlag, // A.1.103
				"Proceed To First Write Flag",
				1, false );

		add( TagKernel8.ReaderContactlessFloorLimit, // A.1.104
				"Reader Contactless Floor Limit",
				6, false );

		add( TagKernel8.ReaderCVMRequiredLimit, // A.1.105
				"Reader CVM Required Limit",
				6, false );

		add( TagKernel8.ReadDataStatus, // A.1.106
				"Read Data Status",
				1, false );

		add( TagKernel8.RelayResistanceAccuracyThreshold, // A.1.109
				"Relay Resistance Accuracy Threshold",
				2, false );

		add( TagKernel8.RelayResistanceTimeExcess, // A.1.110
				"Relay Resistance Time Excess",
				2, false );

		add( TagKernel8.RelayResistanceTransmissionTimeMismatchThreshold, // A.1.111
				"Relay Resistance Transmission Time Mismatch Threshold",
				1, false );

		add( TagEmv.ResponseMessageTemplateFormat2, // A.1.112
				"Response Message Template Format 2",
				0, 253, true );

		add( TagKernel8.RestartIndicator, // A.1.113
				"Restart Indicator",
				2, 5, true );

		add( TagKernel8.SecurityCapability, // A.1.115
				"Security Capability",
				1, false );

		add( TagEmv.ServiceCode, // A.1.116
				"Service Code",
				2, true );

		add( TagKernel8.TagMappingList, // A.1.118
				"Tag Mapping List",
				0, 0xFFFF, false );

		add( TagKernel8.TagsToRead, // A.1.119
				"Tags To Read",
				0, 0xFFFF, false );

		add( TagKernel8.TerminalActionCodeDenial, // A.1.121
				"Terminal Action Code - Denial",
				5, false );

		add( TagKernel8.TerminalActionCodeOnline, // A.1.122
				"Terminal Action Code - Online",
				5, false );

		add( TagEmv.TerminalCapabilities, // A.1.123
				"Terminal Capabilities",
				3, false );

		add( TagEmv.TerminalCountryCode, // A.1.124
				"Terminal Country Code",
				2, false );

		add( TagKernel8.TerminalExpectedTransmissionTimeForRelayResistanceCAPDU, // A.1.125
				"Terminal Expected Transmission Time For Relay Resistance C-APDU",
				2, false );

		add( TagKernel8.TerminalExpectedTransmissionTimeForRelayResistanceRAPDU, // A.1.126
				"Terminal Expected Transmission Time For Relay Resistance R-APDU",
				2, false );

		add( TagEmv.TerminalIdentification, // A.1.127
				"Terminal Identification",
				8, false );

		add( TagEmv.TerminalRiskManagementData, // A.1.129
				"Terminal Risk Management Data",
				8, false );

		add( TagEmv.TerminalType, // A.1.130
				"Terminal Type",
				1, false );

		add( TagEmv.TerminalVerificationResults, // A.1.131
				"Terminal Verification Results",
				5, false );

		add( TagKernel8.TimeoutValue, // A.1.132
				"Timeout Value",
				2, false );

		add( TagEmv.TokenRequestorId, // A.1.133
				"Token Requester ID",
				6, true );

		add( TagEmv.Track1DiscretionaryData, // A.1.134
				"Track 1 Discretionary Data",
				0, 54, true );

		add( TagEmv.Track2DiscretionaryData, // A.1.135
				"Track 2 Discretionary Data",
				0, 16, true );

		add( TagEmv.Track2EquivalentData, // A.1.136
				"Track 2 Equivalent Data",
				0, 19, true );

		add( TagEmv.TransactionCurrencyCode, // A.1.137
				"Transaction Currency Code",
				2, false );

		add( TagEmv.TransactionCurrencyExponent, // A.1.138
				"Transaction Currency Exponent",
				1, false );

		add( TagEmv.TransactionDate, // A.1.139
				"Transaction Date",
				3, false );

		add( TagEmv.TransactionTime, // A.1.140
				"Transaction Time",
				3, false );

		add( TagEmv.TransactionType, // A.1.141
				"Transaction Type",
				1, false );

		add( TagEmv.UnpredictableNumber, // A.1.142
				"Unpredictable Number",
				4, false );

		add( TagKernel8.UserInterfaceRequestData1, // A.1.143
				"User Interface Request Data 1",
				13, false );

		add( TagKernel8.UserInterfaceRequestData2, // A.1.144
				"User Interface Request Data 2",
				13, false );

		add( TagKernel8.WriteDataStatus, // A.1.
				"Write Data Status",
				1, false );
	}
}
