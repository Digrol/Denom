// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8.struct;

import java.util.HashMap;
import org.denom.smartcard.emv.ITagDictionary;
import org.denom.smartcard.emv.TagEmv;
import org.denom.smartcard.emv.TagInfo;

import org.denom.smartcard.emv.TagInfo.Format;

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
	private static void add( int tag, String name, Format format, int minLen, int maxLen, boolean fromCard )
	{
		TagInfo info = new TagInfo( tag, name, format, minLen, maxLen, fromCard, 0, "" );
		tags.put( tag, info );
		tagsByName.put( name, info );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void add( int tag, String name, Format format, int len, boolean fromCard )
	{
		TagInfo info = new TagInfo( tag, name, format, len, len, fromCard, 0, "" );
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

		add(     TagEmv.AccountType,                          "Account Type",                            Format.N,     1,         false ); // A.1.1
		add(     TagEmv.AcquirerIdentifier,                   "Acquirer Identifier",                     Format.N,     6,         false ); // A.1.2
		//                                                    "Active AFL",                                                                // A.1.3
		//                                                    "Active Tag",                                                                // A.1.4
		add(     TagEmv.AdditionalTerminalCapabilities,       "Additional Terminal Capabilities",        Format.B,     5,         false ); // A.1.5
		add(     TagEmv.AmountAuthorisedNumeric,              "Amount, Authorised (Numeric)",            Format.N,     6,         false ); // A.1.6
		add(     TagEmv.AmountOtherNumeric,                   "Amount, Other (Numeric)",                 Format.N,     6,         false ); // A.1.7
		add(     TagEmv.ApplicationCryptogram,                "Application Cryptogram",                  Format.B,     8,          true ); // A.1.8
		add(     TagEmv.ApplicationCurrencyCode,              "Application Currency Code",               Format.N,     2,          true ); // A.1.9
		add(     TagEmv.ApplicationCurrencyExponent,          "Application Currency Exponent",           Format.N,     1,          true ); // A.1.10
		add(     TagEmv.ApplicationExpirationDate,            "Application Expiration Date",             Format.N,     3,          true ); // A.1.11
		add(     TagEmv.AFL,                                  "AFL",                                     Format.B,     4,    248,  true ); // A.1.12
		add(     TagEmv.ApplicationIdentifierTerminal,        "Application Identifier",                  Format.B,     5,     16, false ); // A.1.13
		add(     TagEmv.AIP,                                  "AIP",                                     Format.B,     2,          true ); // A.1.14
		add(     TagEmv.ApplicationLabel,                     "Application Label",                       Format.ANS,   0,     16,  true ); // A.1.15
		add(     TagEmv.PAN,                                  "PAN",                                     Format.CN,    1,     10,  true ); // A.1.16
		add(     TagEmv.PAN_SN,                               "PAN SN",                                  Format.N,     1,          true ); // A.1.17
		add(     TagEmv.ApplicationPreferredName,             "Application Preferred Name",              Format.ANS,   0,     16,  true ); // A.1.18
		add(     TagEmv.ApplicationPriorityIndicator,         "Application Priority Indicator",          Format.B,     1,          true ); // A.1.19
		add(     TagEmv.ASRPD,                                "ASRPD",                                   Format.B,     0,    255,  true ); // A.1.20
		add(     TagEmv.ATC,                                  "ATC",                                     Format.B,     2,          true ); // A.1.21
		add(     TagEmv.ApplicationUsageControl,              "Application Usage Control",               Format.B,     2,          true ); // A.1.22
		add(     TagEmv.ApplicationVersionNumberTerminal,     "Application Version Number (Reader)",     Format.B,     2,         false ); // A.1.23
		add( TagKernel8.AuthenticatedApplicationData,         "Authenticated Application Data",          Format.B,     0,    128,  true ); // A.1.24
		add( TagKernel8.CardholderVerificationDecision,       "Cardholder Verification Decision",        Format.B,     1,          true ); // A.1.25
		add( TagKernel8.CardCapabilitiesInformation,          "Card Capabilities Information",           Format.B,     2,          true ); // A.1.26
		add( TagKernel8.CardDataInputCapability,              "Card Data Input Capability",              Format.B,     1,         false ); // A.1.27
		add( TagKernel8.CardKeyData,                          "Card Key Data",                           Format.B,    64,    132,  true ); // A.1.28
		add( TagKernel8.CardQualifier,                        "Card Qualifier",                          Format.B,     7,          true ); // A.1.29
		add( TagKernel8.CardTVR,                              "Card TVR",                                Format.B,     5,          true ); // A.1.30
		add(     TagEmv.CDOL1,                                "CDOL1",                                   Format.B,     0,    250,  true ); // A.1.31
		add(     TagEmv.CAPublicKeyIndexICC,                  "CA Public Key Index (Card)",              Format.B,     1,          true ); // A.1.33
		add(     TagEmv.CryptogramInformationData,            "Cryptogram Information Data",             Format.B,     1,          true ); // A.1.34
		//                                                    "Crypto Read Data Counter",                                                  // A.1.35
		//                                                    "Crypto Read Record Counter",                                                // A.1.36
		add( TagKernel8.CVMCapabilityCVMRequired,             "CVM Capability - CVM Required",           Format.B,     1,         false ); // A.1.37
		add( TagKernel8.CVMCapabilityNoCVMRequired,           "CVM Capability - No CVM Required",        Format.B,     1,         false ); // A.1.38
		add(     TagEmv.CVMResults,                           "CVM Results",                             Format.B,     3,         false ); // A.1.39
			for( int i = 1; i <= 10; ++i )
		add( TagKernel8.DataEnvelopeX + i,                    "Data Envelope " + Integer.toString( i ),  Format.B,     0,    243,  true ); // A.1.40
		add( TagKernel8.DataEnvelopesToWrite,                 "Data Envelopes To Write",                 Format.B,     0, 0xFFFF, false ); // A.1.41
		//                                                    "Data Envelopes To Write Yet",                                               // A.1.42
		add( TagKernel8.DataNeeded,                           "Data Needed",                             Format.B,     0, 0xFFFF, false ); // A.1.43
		add( TagKernel8.DataRecord,                           "Data Record",                             Format.B,     0, 0xFFFF, false ); // A.1.44
		add( TagKernel8.DataToSend,                           "Data To Send",                            Format.B,     0, 0xFFFF, false ); // A.1.45
		add( TagKernel8.DefaultCDOL1,                         "Default CDOL1",                           Format.B,     0,    250, false ); // A.1.46
		add( TagKernel8.DefaultIADMACOffset,                  "Default IAD MAC Offset",                  Format.B,     1,         false ); // A.1.47
		//                                                    "Device Estimated Time For RR R-APDU",                                       // A.1.48
		//                                                    "Device RR Entropy",                                                         // A.1.49
		add(     TagEmv.DFName,                               "DF Name",                                 Format.B,     5,     16,  true ); // A.1.50
		add( TagKernel8.DiscretionaryDataTagList,             "Discretionary Data Tag List",             Format.B,     0, 0xFFFF, false ); // A.1.51
		add( TagKernel8.DiscretionaryData,                    "Discretionary Data",                      Format.B,     0, 0xFFFF, false ); // A.1.52
		//                                                    "EDA Status",                                                                // A.1.53
		add( TagKernel8.EDA_MAC,                              "Enhanced Data Authentication MAC",        Format.B,     8,          true ); // A.1.54
		add( TagKernel8.ErrorIndication,                      "Error Indication",                        Format.B,     6,         false ); // A.1.55
		add( TagKernel8.ExtendedSDATagList,                   "Extended SDA Tag List",                   Format.B,     0,    255,  true ); // A.1.56
		//                                                    "Extended SDA Tag List Related Data",                                        // A.1.57
		add(     TagEmv.FCIIssuerDiscretionaryData,           "FCI Issuer Discretionary Data",           Format.B,     0,    220,  true ); // A.1.58
		add(     TagEmv.FCIProprietaryTemplate,               "FCI Proprietary Template",                Format.B,     0,    240,  true ); // A.1.59
		add(     TagEmv.FCI,                                  "FCI Template",                            Format.B,     0,    250,  true ); // A.1.60
		//                                                    "GENERATE AC Response Message Data Field"                                    // A.1.61
		add( TagKernel8.HoldTimeValue,                        "Hold Time Value",                         Format.B,     1,         false ); // A.1.62
		add( TagKernel8.IAD_MACOffset,                        "IAD MAC Offset",                          Format.B,     1,          true ); // A.1.63
		add( TagKernel8.ICCECCPublicKey_RSACert,              "ICC ECC Public Key (for RSA Certs)",      Format.B,    32,     66,  true ); // A.1.64
		add(     TagEmv.ICC_PublicKeyCertificate,             "ICC Public Key Certificate",              Format.B,     0,    248,  true ); // A.1.65
		add(     TagEmv.ICC_PublicKeyExponent,                "ICC RSA Public Key Exponent",             Format.B,     1,      3,  true ); // A.1.66
		add(     TagEmv.ICC_PublicKeyRemainder,               "ICC RSA Public Key Remainder",            Format.B,     0,    255,  true ); // A.1.67
		add(     TagEmv.InterfaceDeviceSerialNumber,          "Interface Device Serial Number",          Format.AN,    8,         false ); // A.1.68
		add(     TagEmv.IAD,                                  "Issuer Application Data",                 Format.B,     0,     32,  true ); // A.1.69
		add( TagKernel8.IAD_MAC,                              "Issuer Application Data MAC",             Format.B,     8,         false ); // A.1.70
		add(     TagEmv.IssuerCodeTableIndex,                 "Issuer Code Table Index",                 Format.N,     1,          true ); // A.1.71
		add(     TagEmv.IIN,                                  "Issuer Identification Number",            Format.N,     3,          true ); // A.1.72
		add(     TagEmv.IINE,                                 "Issuer Identification Number Extended",   Format.N,     3,      4,  true ); // A.1.73
		add(     TagEmv.IssuerPublicKeyCertificate,           "Issuer Public Key Certificate",           Format.B,     0,    248,  true ); // A.1.74
		add(     TagEmv.IssuerPublicKeyExponent,              "Issuer RSA Public Key Exponent",          Format.B,     1,      3,  true ); // A.1.75
		add(     TagEmv.IssuerPublicKeyRemainder,             "Issuer RSA Public Key Remainder",         Format.B,     0,    255,  true ); // A.1.76
		add( TagKernel8.KernelConfiguration,                  "Kernel Configuration",                    Format.B,     2,         false ); // A.1.77
		//                                                    "Kernel Decision",                                                           // A.1.78
		add( TagKernel8.KernelKeyData,                        "Kernel Key Data",                         Format.B,     0,    132, false ); // A.1.79
		add( TagKernel8.KernelQualifier,                      "Kernel Qualifier",                        Format.B,     8,         false ); // A.1.80
		add( TagKernel8.KernelReservedTVRMask,                "Kernel Reserved TVR Mask",                Format.B,     5,         false ); // A.1.81
		add(     TagEmv.LanguagePreference,                   "Language Preference",                     Format.AN,    2,      8,  true ); // A.1.82
		//                                                    "Last ERRD Response",                                                        // A.1.83
		add(     TagEmv.LogEntry,                             "Log Entry",                               Format.B,     2,          true ); // A.1.84
		add( TagKernel8.MaximumRRGracePeriod,                 "Maximum Relay Resistance Grace Period",   Format.B,     2,         false ); // A.1.85
		//                                                    "Max Time For Processing RR APDU",                                           // A.1.86
		//                                                    "Measured RR Processing Time",                                               // A.1.87
		add(     TagEmv.MerchantCategoryCode,                 "Merchant Category Code",                  Format.N,     2,         false ); // A.1.88
		add(     TagEmv.MerchantIdentifier,                   "Merchant Identifier",                     Format.ANS,  15,         false ); // A.1.89
		add(     TagEmv.MerchantNameAndLocation,              "Merchant Name and Location",              Format.ANS,   0, 0xFFFF, false ); // A.1.90
		add( TagKernel8.MessageHoldTime,                      "Message Hold Time",                       Format.N,     3,         false ); // A.1.91
		//                                                    "Message Identifier",                                                        // A.1.92
		add( TagKernel8.MessageIdentifiersOnRestart,          "Message Identifiers On Restart",          Format.B,     0,     32, false ); // A.1.93
		//                                                    "Message To Validate",                                                       // A.1.94
		add( TagKernel8.MinimumRRGracePeriod,                 "Minimum Relay Resistance Grace Period",   Format.B,     2,         false ); // A.1.95
		//                                                    "Min Time For Processing RR APDU",                                           // A.1.96
		//                                                    "Next Cmd",                                                                  // A.1.97
		add( TagKernel8.OutcomeParameterSet,                  "Outcome Parameter Set",                   Format.B,     8,         false ); // A.1.98
		add(     TagEmv.PAR,                                  "Payment Account Reference",               Format.AN,   29,          true ); // A.1.99
		add(     TagEmv.PDOL,                                 "PDOL",                                    Format.B,     0,    240,  true ); // A.1.100
		//                                                    "PDOL Related Data",                                                         // A.1.101
		//                                                    "PDOL Values",                                                               // A.1.102
		add( TagKernel8.ProceedToFirstWriteFlag,              "Proceed To First Write Flag",             Format.B,     1,         false ); // A.1.103
		add( TagKernel8.ReaderContactlessFloorLimit,          "Reader Contactless Floor Limit",          Format.N,     6,         false ); // A.1.104
		add( TagKernel8.ReaderCVMRequiredLimit,               "Reader CVM Required Limit",               Format.N,     6,         false ); // A.1.105
		add( TagKernel8.ReadDataStatus,                       "Read Data Status",                        Format.B,     1,         false ); // A.1.106
		//                                                    "Read Data Tags To Validate Yet",                                            // A.1.107
		//                                                    "Reference Control Parameter",                                               // A.1.108
		add( TagKernel8.RR_AccuracyThreshold,                 "Relay Resistance Accuracy Threshold",     Format.B,     2,         false ); // A.1.109
		add( TagKernel8.RR_TimeExcess,                        "RR Time Excess",                          Format.B,     2,         false ); // A.1.110
		add( TagKernel8.RR_TransmissionTimeMismatchThreshold, "RR Transmission Time Mismatch Threshold", Format.B,     1,         false ); // A.1.111
		add(     TagEmv.ResponseMessageTemplateFormat2,       "Response Message Template Format 2",      Format.B,     0,    253,  true ); // A.1.112
		add( TagKernel8.RestartIndicator,                     "Restart Indicator",                       Format.B,     2,      5,  true ); // A.1.113
		//                                                    "RRP Counter",                                                               // A.1.114
		add( TagKernel8.SecurityCapability,                   "Security Capability",                     Format.B,     1,         false ); // A.1.115
		add(     TagEmv.ServiceCode,                          "Service Code",                            Format.N,     2,          true ); // A.1.116
		//                                                    "Start Time",                                                                // A.1.117
		add( TagKernel8.TagMappingList,                       "Tag Mapping List",                        Format.B,     0, 0xFFFF, false ); // A.1.118
		add( TagKernel8.TagsToRead,                           "Tags To Read",                            Format.B,     0, 0xFFFF, false ); // A.1.119
		//                                                    "Tags To Read Yet",                                                          // A.1.120
		add( TagKernel8.TerminalActionCodeDenial,             "Terminal Action Code - Denial",           Format.B,     5,         false ); // A.1.121
		add( TagKernel8.TerminalActionCodeOnline,             "Terminal Action Code - Online",           Format.B,     5,         false ); // A.1.122
		add(     TagEmv.TerminalCapabilities,                 "Terminal Capabilities",                   Format.B,     3,         false ); // A.1.123
		add(     TagEmv.TerminalCountryCode,                  "Terminal Country Code",                   Format.N,     2,         false ); // A.1.124
		add( TagKernel8.TerminalExpectedTimeForRRCAPDU,       "Terminal Expected Time For RR C-APDU",    Format.B,     2,         false ); // A.1.125
		add( TagKernel8.TerminalExpectedTimeForRRRAPDU,       "Terminal Expected Time For RR R-APDU",    Format.B,     2,         false ); // A.1.126
		add(     TagEmv.TerminalIdentification,               "Terminal Identification",                 Format.AN,    8,         false ); // A.1.127
		//                                                    "Terminal RR Entropy",                                                       // A.1.128
		add(     TagEmv.TerminalRiskManagementData,           "Terminal Risk Management Data",           Format.B,     8,         false ); // A.1.129
		add(     TagEmv.TerminalType,                         "Terminal Type",                           Format.N,     1,         false ); // A.1.130
		add(     TagEmv.TerminalVerificationResults,          "Terminal Verification Results",           Format.B,     5,         false ); // A.1.131
		add( TagKernel8.TimeoutValue,                         "Timeout Value",                           Format.B,     2,         false ); // A.1.132
		add(     TagEmv.TokenRequestorId,                     "Token Requester ID",                      Format.N,     6,          true ); // A.1.133
		add(     TagEmv.Track1DiscretionaryData,              "Track 1 Discretionary Data",              Format.ANS,   0,     54,  true ); // A.1.134
		add(     TagEmv.Track2DiscretionaryData,              "Track 2 Discretionary Data",              Format.CN,    0,     16,  true ); // A.1.135
		add(     TagEmv.Track2EquivalentData,                 "Track 2 Equivalent Data",                 Format.B,     0,     19,  true ); // A.1.136
		add(     TagEmv.TransactionCurrencyCode,              "Transaction Currency Code",               Format.N,     2,         false ); // A.1.137
		add(     TagEmv.TransactionCurrencyExponent,          "Transaction Currency Exponent",           Format.N,     1,         false ); // A.1.138
		add(     TagEmv.TransactionDate,                      "Transaction Date",                        Format.N,     3,         false ); // A.1.139
		add(     TagEmv.TransactionTime,                      "Transaction Time",                        Format.N,     3,         false ); // A.1.140
		add(     TagEmv.TransactionType,                      "Transaction Type",                        Format.N,     1,         false ); // A.1.141
		add(     TagEmv.UnpredictableNumber,                  "Unpredictable Number",                    Format.B,     4,         false ); // A.1.142
		add( TagKernel8.UserInterfaceRequestData1,            "User Interface Request Data 1",           Format.B,    13,         false ); // A.1.143
		add( TagKernel8.UserInterfaceRequestData2,            "User Interface Request Data 2",           Format.B,    13,         false ); // A.1.144
		add( TagKernel8.WriteDataStatus,                      "Write Data Status",                       Format.B,     1,         false ); // A.1.145


		add(     TagEmv.CardholderName,                       "Cardholder Name",                         Format.ANS,   2,     26,  true );
		add(     TagEmv.ICC_PublicKeyCertificate,             "ICC Public Key Certificate",              Format.B,     0,    255,  true );
	}
}
