// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.smartcard.emv;

/**
 * BerTLV Tags for data elements, defined in EMV 4.4, Book 3. Application specification, Annex A. Data Elements Dictionary.
 */
public class TagEmv
{
	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------
	/**
	 * Account Type.<br>
	 * Indicates the type of account selected on the terminal, coded as specified in Annex G.
	 */
	public static final int AccountType
	               = 0x5F57; //  --              |  1         |  n 2         |  Terminal              |

	/**
	 * Acquirer Identifier.<br>
	 * Uniquely identifies the acquirer within each payment system.
	 */
	public static final int AcquirerIdentifier
	               = 0x9F01; //  --              |  6         |  n 6-11      |  Terminal              |

	/**
	 * Additional Terminal Capabilities.<br>
	 * Indicates the data input and output capabilities of the terminal.
	 */
	public static final int AdditionalTerminalCapabilities
	               = 0x9F40; //  --              |  5         |  b           |  Terminal              |

	/**
	 * Amount, Authorised (Binary).<br>
	 * Authorised amount of the transaction (excluding adjustments).
	 */
	public static final int AmountAuthorisedBinary
	               = 0x81  ; //  --              |  4         |  b           |  Terminal              |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Amount, Authorised (Numeric).<br>
	 * Authorised amount of the transaction (excluding adjustments).
	 */
	public static final int AmountAuthorisedNumeric
	               = 0x9F02; //  --              |  6         |  n 12        |  Terminal              |

	/**
	 * Amount, Other (Binary).<br>
	 * Secondary amount associated with the transaction representing a cashback amount.
	 */
	public static final int AmountOtherBinary
	               = 0x9F04; //  --              |  4         |  b           |  Terminal              |

	/**
	 * Amount, Other (Numeric).<br>
	 * Secondary amount associated with the transaction representing a cashback amount.
	 */
	public static final int AmountOtherNumeric
	               = 0x9F03; //  --              |  6         |  n 12        |  Terminal              |

	/**
	 * Amount, Reference Currency.<br>
	 * Authorised amount expressed in the reference currency.
	 */
	public static final int AmountReferenceCurrency
	               = 0x9F3A; //  --              |  4         |  b           |  Terminal              |

	/**
	 * Application Cryptogram.<br>
	 * Cryptogram returned by the ICC in response of the GENERATE AC command.
	 */
	public static final int ApplicationCryptogram
	               = 0x9F26; //  '77', '80'      |  8         |  b           |  ICC                   |

	/**
	 * Application Currency Code.<br>
	 * Indicates the currency in which the account is managed according to ISO 4217.
	 */
	public static final int ApplicationCurrencyCode
	               = 0x9F42; //  '70', '77'      |  2         |  n 3         |  ICC                   |

	/**
	 * Application Currency Exponent.<br>
	 * Indicates the implied position of the decimal point
	 * from the right of the amount represented according to ISO 4217.
	 */
	public static final int ApplicationCurrencyExponent
	               = 0x9F44; //  '70', '77'      |  1         |  n 1         |  ICC                   |

	/**
	 * Application Discretionary Data.<br>
	 * Issuer or payment system specified data relating to the application.
	 */
	public static final int ApplicationDiscretionaryData
	               = 0x9F05; //  '70', '77'      |  1-32      |  b           |  ICC                   |

	/**
	 * Application Effective Date.<br>
	 * Date from which the application may be used.
	 */
	public static final int ApplicationEffectiveDate
	               = 0x5F25; //  '70', '77'      |  3         |  n 6 YYMMDD  |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Application Expiration Date.<br>
	 * Date after which application expires.
	 */
	public static final int ApplicationExpirationDate
	               = 0x5F24; //  '70', '77'      |  3         |  n 6 YYMMDD  |  ICC                   |

	/**
	 * Application File Locator -- AFL.<br>
	 * Indicates the location (SFI, range of records) of the AEFs related to a given application.
	 */
	public static final int AFL
	               = 0x94  ; //  '77', '80'      |  <= 252    |  var.        |  ICC                   |

	/**
	 * Application Dedicated File Name -- ADF.<br>
	 * Identifies the application as described in ISO/IEC 7816-5.
	 */
	public static final int ApplicationDedicatedFileName
	               = 0x4F  ; //  '61'            |  5-16      |  b           |  ICC                   |

	/**
	 * Application Identifier (AID) – terminal.<br>
	 * Identifies the application as described in ISO/IEC 7816-5.
	 */
	public static final int ApplicationIdentifierTerminal
	               = 0x9F06; //  --              |  5-16      |  b           |  Terminal              |

	/**
	 * Application Interchange Profile -- AIP.<br>
	 * Indicates the capabilities of the card to support specific functions in the application.
	 */
	public static final int AIP
	               = 0x82  ; //  '77', '80'      |  2         |  b           |  ICC                   |

	/**
	 * Application Label.<br>
	 * Mnemonic associated with the AID according to ISO/IEC 7816-5.
	 */
	public static final int ApplicationLabel
	               = 0x50  ; //  '61', 'A5'      |  1-16      |  --          |  ICC                   |

	/**
	 * Application Preferred Name.<br>
	 * Preferred mnemonic associated with the AID.
	 */
	public static final int ApplicationPreferredName
	               = 0x9F12; //  '61', 'A5'      |  1-16      |  --          |  ICC                   |

	/**
	 * Application Primary Account Number -- PAN.<br>
	 * Valid cardholder account number.
	 */
	public static final int PAN
	               = 0x5A  ; //  '70', '77'      |  <= 10     |  cn <= 19    |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Application Primary Account Number -- PAN Sequence Number.<br>
	 * Identifies and differentiates cards with the same PAN.
	 */
	public static final int PAN_SN
	               = 0x5F34; //  '70', '77'      |  1         |  n 2         |  ICC                   |

	/**
	 * Application Priority Indicator.<br>
	 * Indicates the priority of a given application or group of applications in a directory.
	 */
	public static final int ApplicationPriorityIndicator
	               = 0x87  ; //  '61', 'A5'      |  1         |  b           |  ICC                   |

	/**
	 * Application Reference Currency.<br>
	 * 1-4 currency codes used between the terminal and the ICC when the Transaction Currency Code
	 * is different from the Application Currency Code; each code is 3 digits according to ISO 4217.
	 */
	public static final int ApplicationReferenceCurrency
	               = 0x9F3B; //  '70', '77'      |  2-8       |  n 3         |  ICC                   |

	/**
	 * Application Reference Currency Exponent.<br>
	 * Indicates the implied position of the decimal point from the right of the amount,
	 * for each of the 1-4 reference currencies represented according to ISO 4217.
	 */
	public static final int ApplicationReferenceCurrencyExponent
	               = 0x9F43; //  '70', '77'      |  1-4       |  n 1         |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/// Application Selection Indicator.
	// For an application in the ICC to be supported by an application in the terminal,
	// the Application Selection Indicator indicates whether the associated AID in the terminal
	// must match the AID in the card exactly, including the length of the AID, or only up
	// to the length of the AID in the terminal.
	// There is only one Application Selection Indicator per AID supported by the terminal.
	//            |  --       |  --              |  --        |  --          |  Terminal              |

	/**
	 * Application Selection Registered Proprietary Data (ASRPD).<br>
	 * Proprietary data allowing for proprietary processing during application selection.
	 * Proprietary data is identified using Proprietary Data Identifiers that are managed 
	 * by EMVCo and their usage by the Application Selection processing is according to their 
	 * intended usage, as agreed by EMVCo during registration.
	 */
	public static final int ASRPD
	               = 0x9F0A; //  '73', 'BF0C'    |  var.      | b, Book1,12.5|  ICC                   |
	
	/**
	 * Application Template.<br>
	 * Contains one or more data objects relevant to an application directory entry
	 * according to ISO/IEC 7816-5.
	 */
	public static final int ApplicationTemplate
	               = 0x61  ; //  '70'            |  <= 252    |  b           |  ICC                   |

	/**
	 * Application Transaction Counter -- ATC.<br>
	 * Counter maintained by the application in the ICC (incrementing the ATC is managed by the ICC).
	 */
	public static final int ATC
	               = 0x9F36; //  '77', '80'      |  2         |  b           |  ICC                   |

	/**
	 * Application Usage Control.<br>
	 * Indicates issuer’s specified restrictions on the geographic usage
	 * and services allowed for the application.
	 */
	public static final int ApplicationUsageControl
	               = 0x9F07; //  '70', '77'      |  2         |  b           |  ICC                   |

	/**
	 * Application Version Number ICC.<br>
	 * Version number assigned by the payment system for the application.
	 */
	public static final int ApplicationVersionNumberICC
	               = 0x9F08; //  '70', '77'      |  2         |  b           |  ICC                   |

	/**
	 * Application Version Number Terminal.<br>
	 * Version number assigned by the payment system for the application.
	 */
	public static final int ApplicationVersionNumberTerminal
	               = 0x9F09; //  --              |  2         |  b           |  Terminal              |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Authorisation Code.<br>
	 * Value generated by the authorisation authority for an approved transaction.
	 */
	public static final int AuthorisationCode
	               = 0x89  ; //  --              |  6         |  --          |  Issuer                |

	/**
	 * Authorisation Response Code.<br>
	 * Code that defines the disposition of a message.
	 */
	public static final int AuthorisationResponseCode
	               = 0x8A  ; //  --              |  2         |  an 2        |  Issuer/Terminal       |

	/// Authorisation Response Cryptogram -- ARPC.
	// Cryptogram generated by the issuer and used by the card
	// to verify that the response came from the issuer.
	//            |  --       |  --              |  4, 8      |  b           |  Issuer                |

	/**
	 * Bank Identifier Code -- BIC.<br>
	 * Uniquely identifies a bank as defined in ISO 9362.
	 */
	public static final int BankIdentifierCode
	               = 0x5F54; //  'BF0C', '73'    |  8, 11     |  var.        |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/// Biometric Encryption Key -- BEK.<br>
	// An AES-128 key generated from the Biometric Key Seed, that is used to encrypt/decrypt the 
	// BDB constructed on the Biometric Processing Application.
	//            |  --       |  --              |  16        |  b           |  Terminal              |

	/**
	 * Biometric Header Template -- BHT.<br>
	 * A template defined in ISO/IEC 19785-3, that is nested under the BIT.
	 */
	public static final int BiometricHeaderTemplate
	               = 0xA1  ; //  '7F60'          |  var.      |  b           |  ICC/Terminal          |

	/**
	 * Biometric Information Template -- BIT.<br>
	 * A template defined in ISO/IEC 19785-3, that describes information regarding the biometric 
	 * format and solution supported in a card/terminal.
	 */
	public static final int BiometricInformationTemplate
	               = 0x7F60; //  'BF4A', 'BF4B'  |  var.      |  b           |  ICC/Terminal          |

	/// Biometric Key Seed.<br>
	// A random number generated by the terminal, that is used as the seed to generate
	// the Biometric Encryption Key (BEK) and Biometric MAC Key (BMK)
	//            |  --       |  --              |  Npe, Nic  |  b           |  Terminal              |

	// Biometric MAC Key (BMK).
	// A key generated from the Biometric Key Seed, that is used to ensure the integrity of the BDB. 
	//            |  --       |  --              |  32        |  b           |  Terminal              |

	/**
	 * Biometric Solution ID.<br>
	 * A unique identifier assigned by EMVCo that is used to identify a biometric program, regional 
	 * or global, supported by the card or terminal. The Biometric Solution ID is referred to within 
	 * ISO/IEC 19785-3 as the "Index".
	 */
	public static final int BiometricSolutionId
	               = 0x90  ; //  'A1', 'BF4E'    |  var.      |  b           |  ICC/Terminal          |

	/**
	 * Biometric Subtype.<br>
	 * A data element defined in ISO/IEC 19785-3, that describes the subtype of
	 * the Biometric Type supported by the card or terminal, as shown in Table 50.
	 */
	public static final int BiometricSubtype
	               = 0x82  ; //  'A1'            |  1         |  b           |  ICC/Terminal          |

	/**
	 * Biometric Terminal Capabilities.<br>
	 * A data element that identifies the Biometric CVM capabilities of the terminal.
	 */
	public static final int BiometricTerminalCapabilities
	               = 0x9F30; //  --              |  3         |  b           |  Terminal              |

	/**
	 * Biometric Try Counters Template.<br>
	 * A template that contains one or more of the following Biometric Try Counters:<ul>
	 * <li>Facial Try Counter</li>
	 * <li>Finger Try Counter</li>
	 * <li>Iris Try Counter</li>
	 * <li>Palm Try Counter</li>
	 * <li>Voice Try Counter</li>
	 */
	public static final int BiometricTryCountersTemplate
	               = 0xBF4C; //  --              |  var.      |  b           |  ICC                   |

	/**
	 * Biometric Type.<br>
	 * A data element defined in ISO/IEC 19785-3, that describes the type of biometrics supported 
	 * by the card or terminal among facial, finger, iris, palm and voice, as shown in Table 49.
	 */
	public static final int BiometricType
	               = 0x81  ; //  'A1', 'BF4E'    |  var.      |  b           |  ICC/Terminal          |

	/**
	 * Biometric Verification Data Template.<br>
	 * A template that contains the TLV-coded values for the data to be included in the VERIFY command.
	 * The Biometric Verification Data Template contains Biometric Type ('81'),
	 * Biometric Solution ID ('90'), Enciphered Biometric Key Seed ('DF50'),
	 * Enciphered Biometric Data (tag 'DF51'), and MAC of Enciphered Biometric Data (tag 'DF52').
	 */
	public static final int BiometricVerificationDataTemplate
	               = 0xBF4E; //  --              |  var.      |  b           |  Terminal              |

	/**
	 * Card BIT Group Template.<br>
	 * A template in the card that contains one or more Biometric Information Templates (BITs).
	 */
	public static final int CardBITGroupTemplate
	               = 0x9F31; //  '70'            |  var.      |  b           |  ICC                   |
	
	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Card Risk Management Data Object List 1 -- CDOL1.<br>
	 * List of data objects (tag and length) to be passed to the ICC in the first GENERATE AC command.
	 */
	public static final int CDOL1
	               = 0x8C  ; //  '70', '77'      |  <= 252    |  b           |  ICC                   |

	/**
	 * Card Risk Management Data Object List 2 -- CDOL2.<br>
	 * List of data objects (tag and length) to be passed to the ICC in the first GENERATE AC command.
	 */
	public static final int CDOL2
	               = 0x8D  ; //  '70', '77'      |  <= 252    |  b           |  ICC                   |

	/// Card Status Update -- CSU.
	// Contains data sent to the ICC to indicate whether the issuer approves or
	// declines the transaction, and to initiate actions specified by the issuer.
	// Transmitted to the card in Issuer Authentication Data.
	//            |  --       |  --              |  4         |  b           |  Issuer                |

	/**
	 * Cardholder Name.<br>
	 * Indicates cardholder name according to ISO 7813.
	 */
	public static final int CardholderName
	               = 0x5F20; //  '70', '77'      |  2-26      |  ans 2-26    |  ICC                   |

	/**
	 * Cardholder Name Extended.<br>
	 * Indicates the whole cardholder name when greater than 26 characters
	 * using the same coding convention as in ISO 7813.
	 */
	public static final int CardholderNameExtended
	               = 0x9F0B; //  '70', '77'      |  27-45     |  ans 27-45   |  ICC                   |

	/**
	 * Cardholder Verification Method (CVM) List.<br>
	 * Identifies a method of verification of the cardholder supported by the application.
	 */
	public static final int CardholderVerificationMethodList
	               = 0x8E  ; //  '70', '77'      |  10-252    |  b           |  ICC                   |

	/**
	 * Cardholder Verification Method (CVM) Results.<br>
	 * Indicates the results of the last CVM performed.
	 */
	public static final int CVM_Results
	               = 0x9F34; //  --              |  3         |  b           |  Terminal              |

	/// Certification Authority Public Key Check Sum.
	// A check value calculated on the concatenation of all parts of the Certification Authority
	// Public Key (RID, Certification Authority Public Key Index, Certification Authority Public
	// Key Modulus, Certification Authority Public Key Exponent) using SHA-1
	//            |  --       |  --              |  20        |  b           |  Terminal              |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/// Certification Authority Public Key Exponent.
	// Value of the exponent part of the Certification Authority Public Key.
	//            |  --       |  --              |  1, 3      |  b           |  Terminal              |

	/**
	 * Certification Authority Public Key Index ICC.<br>
	 * Identifies the certification authority’s public key in conjunction with the RID.
	 */
	public static final int CertificationAuthorityPublicKeyIndexICC
	               = 0x8F  ; //  '70', '77'      |  1         |  b           |  ICC                   |

	/**
	 * Certification Authority Public Key Index Terminal.<br>
	 * Identifies the certification authority’s public key in conjunction with the RID.
	 */
	public static final int CertificationAuthorityPublicKeyIndexTerminal
	               = 0x9F22; //  --              |  1         |  b           |  Terminal              |

	/// Certification Authority Public Key Modulus.
	// Value of the modulus part of the Certification Authority Public Key.
	//            |  --       |  --              | NCA <= 248 |  b           |  Terminal              |

	/**
	 * Command Template.<br>
	 * Identifies the data field of a command message.
	 */
	public static final int CommandTemplate
	               = 0x83  ; //  --              |  var.      |  b           |  Terminal              |

	/**
	 * Cryptogram Information Data.<br>
	 * Indicates the type of cryptogram and the actions to be performed by the terminal.
	 */
	public static final int CryptogramInformationData
	               = 0x9F27; //  '77', '80'      |  1         |  b           |  ICC                   |

	/**
	 * Data Authentication Code (DAC).<br>
	 * An issuer assigned value that is retained by the terminal during the verification process 
	 * of the Signed Static Application Data.
	 */
	public static final int DAC
	               = 0x9F45; //  --              |  2         |  b           |  ICC                   |

	/**
	 * Dedicated File Name -- DF.<br>
	 * Identifies the name of the DF as described in ISO/IEC 7816-4.
	 */
	public static final int DedicatedFileName
	               = 0x84  ; //  '6F'            |  5-16      |  b           |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/// Default Dynamic Data Authentication Data Object List -- DDOL.
	// DDOL to be used for constructing the INTERNAL AUTHENTICATE command
	// if the DDOL in the card is not present.
	//            |  --       |  --              |  var.      |  b           |  Terminal              |

	/// Default Transaction Certificate Data Object List -- TDOL.
	// TDOL to be used for generating the TC Hash Value if the TDOL in the card is not present.
	//            |  --       |  --              |  var.      |  b           |  Terminal              |

	/**
	 * Directory Definition File Name -- DDF.<br>
	 * Identifies the name of a DF associated with a directory.
	 */
	public static final int DirectoryDefinitionFileName
	               = 0x9D  ; //  '61'            |  5-16      |  b           |  ICC                   |

	/**
	 * Directory Discretionary Template.<br>
	 * Issuer discretionary part of the directory according to ISO/IEC 7816-5.
	 */ 
	public static final int DirectoryDiscretionaryTemplate
	               = 0x73  ; //  '61'            |  <= 252    |  var.        |  ICC                   |

	/**
	 * Dynamic Data Authentication Data Object List -- DDOL.<br>
	 * List of data objects (tag and length) to be passed to the ICC
	 * in the INTERNAL AUTHENTICATE command.
	 */
	public static final int DDOL
	               = 0x9F49; //  '70', '77'      |  <= 252    |  b           |  ICC                   |

	/// Enciphered Personal Identification Number Data -- PIN.
	// Transaction PIN enciphered at the PIN pad for online verification or for offline
	// verification if the PIN pad and IFD are not a single integrated device.
	//            |  --       |  --              |  8         |  b           |  Terminal              |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * File Control Information (FCI) Issuer Discretionary Data.<br>
	 * Issuer discretionary part of the FCI.
	 */
	public static final int FileControlInformationIssuerDiscretionaryData
	               = 0xBF0C; //  'A5'            |  <= 222    |  var.        |  ICC                   |

	/**
	 * File Control Information (FCI) Proprietary Template.<br>
	 * Identifies the data object proprietary to this specification in the FCI template
	 * according to ISO/IEC 7816-4.
	 */
	public static final int FileControlInformationProprietaryTemplate
	               = 0xA5  ; //  '6F'            |  var.      |  var.        |  ICC                   |

	/**
	 * File Control Information (FCI) Template.<br>
	 * Identifies the FCI template according to ISO/IEC 7816-4.
	 */
	public static final int FileControlInformationTemplate
	               = 0x6F  ; //  --              |  <= 252    |  var.        |  ICC                   |

	/**
	 * ICC Dynamic Number.<br>
	 * Time-variant number generated by the ICC, to be captured by the terminal.
	 */
	public static final int ICC_DynamicNumber
	               = 0x9F4C; //  --              |  2-8       |  b           |  ICC                   |

	/**
	 * Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate.<br>
	 * ICC PIN Encipherment Public Key certified by the issuer.
	 */
	public static final int ICC_PINEnciphermentPublicKeyCertificate
	               = 0x9F2D; //  '70', '77'      |  NI        |  b           |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent.<br>
	 * ICC PIN Encipherment Public Key Exponent used for PIN encipherment.
	 */
	public static final int ICC_PINEnciphermentPublicKeyExponent
	               = 0x9F2E; //  '70', '77'      |  1, 3      |  b           |  ICC                   |

	/**
	 * Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder.<br>
	 * Remaining digits of the ICC PIN Encipherment Public Key Modulus.
	 */
	public static final int ICC_PINEnciphermentPublicKeyRemainder
	               = 0x9F2F; //  '70', '77'      |  NPE-NI+42 |  b           |  ICC                   |

	/**
	 * Integrated Circuit Card (ICC) Public Key Certificate.<br>
	 * ICC Public Key certified by the issuer.
	 */
	public static final int ICC_PublicKeyCertificate
	               = 0x9F46; //  '70', '77'      |  NI        |  b           |  ICC                   |

	/**
	 * Integrated Circuit Card (ICC) Public Key Exponent.<br>
	 * ICC Public Key Exponent used for the verification of the Signed Dynamic Application Data.
	 */
	public static final int ICC_PublicKeyExponent
	               = 0x9F47; //  '70', '77'      |  1-3       |  b           |  ICC                   |

	/**
	 * Integrated Circuit Card (ICC) Public Key Remainder.<br>
	 * Remaining digits of the ICC Public Key Modulus.
	 */
	public static final int ICC_PublicKeyRemainder
	               = 0x9F48; //  '70', '77'      |  NIC-NI+42 |  b           |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Interface Device Serial Number -- IFD.<br>
	 * Unique and permanent serial number assigned to the IFD by the manufacturer.
	 */
	public static final int InterfaceDeviceSerialNumber
	               = 0x9F1E; //  --              |  8         |  an 8        |  Terminal              |

	/**
	 * International Bank Account Number -- IBAN.<br>
	 * Uniquely identifies the account of a customer at a financial institution as defined in ISO 13616.
	 */
	public static final int InternationalBankAccountNumber
	               = 0x5F53; //  'BF0C', '73'    |  <= 34     |  var.        |  ICC                   |

	/**
	 * Issuer Action Code - Default.<br>
	 * Specifies the issuer’s conditions that cause a transaction to be rejected if it might have
	 * been approved online, but the terminal is unable to process the transaction online.
	 */
	public static final int IssuerActionCodeDefault
	               = 0x9F0D; //  '70', '77'      |  5         |  b           |  ICC                   |

	/**
	 * Issuer Action Code - Denial.<br>
	 * Specifies the issuer’s conditions that cause the denial 
	 * of a transaction without attempt to go online.
	 */
	public static final int IssuerActionCodeDenial
	               = 0x9F0E; //  '70', '77'      |  5         |  b           |  ICC                   |

	/**
	 * Issuer Action Code - Online.<br>
	 * Specifies the issuer’s conditions that cause a transaction to be transmitted online.
	 */
	public static final int IssuerActionCodeOnline
	               = 0x9F0F; //  '70', '77'      |  5         |  b           |  ICC                   |

	/**
	 * Issuer Application Data.<br>
	 * Contains proprietary application data for transmission to the issuer in an online transaction.<br>
	 * Note: For CCD-compliant applications, Annex C, section C7 defines the specific coding of the
	 *       Issuer Application Data (IAD). To avoid potential conflicts with CCD-compliant
	 *       applications, it is strongly recommended that the IAD data element in an application
	 *       that is not CCD-compliant should not use the coding for a CCD-compliant application.
	 */
	public static final int IssuerApplicationData
	               = 0x9F10; //  '77', '80'      |  <= 32     |  b           |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Issuer Authentication Data.<br>
	 * Data sent to the ICC for online issuer authentication.
	 */
	public static final int IssuerAuthenticationData
	               = 0x91  ; //  --              |  8-16      |  b           |  Issuer                |

	/**
	 * Issuer Code Table Index.<br>
	 * Indicates the code table according to ISO/IEC 8859
	 * for displaying the Application Preferred Name.
	 */
	public static final int IssuerCodeTableIndex
	               = 0x9F11; //  'A5'            |  1         |  n 2         |  ICC                   |

	/**
	 * Issuer Country Code.<br>
	 * Indicates the country of the issuer according to ISO 3166.
	 */
	public static final int IssuerCountryCode
	               = 0x5F28; //  '70', '77'      |  2         |  n 3         |  ICC                   |

	/**
	 * Issuer Country Code (alpha2 format).<br>
	 * Indicates the country of the issuer as defined in ISO 3166 (using a 2 char alphabetic code).
	 */ 
	public static final int IssuerCountryCodeAlpha2Format
	               = 0x5F55; //  'BF0C', '73'    |  2         |  a 2         |  ICC                   |

	/**
	 * Issuer Country Code (alpha3 format).<br>
	 * Indicates the country of the issuer as defined in ISO 3166
	 * (using a 3 character alphabetic code).
	 */
	public static final int IssuerCountryCodeAlpha3Format
	               = 0x5F56; //  'BF0C', '73'    |  3         |  a 3         |  ICC                   |

	/**
	 * Issuer Identification Number -- IIN.<br>
	 * The number that identifies the major industry and the card issuer and that forms the first 
	 * part of the Primary Account Number (PAN).
	 */
	public static final int IssuerIdentificationNumber
	               = 0x42  ; //  'BF0C', '73'    |  3         |  n 6         |  ICC                   |

	/**
	 * Issuer Public Key Certificate.<br>
	 * Issuer public key certified by a certification authority.
	 */
	public static final int IssuerPublicKeyCertificate
	               = 0x90  ; //  '70', '77'      |  NCA       |  b           |  ICC                   |

	/**
	 * Issuer Public Key Exponent.<br>
	 * Issuer public key exponent used for the verification of the Signed Static Application
	 * Data and the ICC Public Key Certificate.
	 */
	public static final int IssuerPublicKeyExponent
	               = 0x9F32; //  '70', '77'      |  1-3       |  b           |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Issuer Public Key Remainder.<br>
	 * Remaining digits of the Issuer Public Key Modulus.
	 */
	public static final int IssuerPublicKeyRemainder
	               = 0x92  ; //  '70', '77'      |  NI-NCA+36 |  b           |  ICC                   |

	/**
	 * Issuer Script Command.<br>
	 * Contains a command for transmission to the ICC.
	 */
	public static final int IssuerScriptCommand
	               = 0x86  ; //  '71', '72'      |  <= 261    |  b           |  Issuer                |

	/**
	 * Issuer Script Identifier.<br>
	 * Identification of the Issuer Script.
	 */
	public static final int IssuerScriptIdentifier
	               = 0x9F18; //  '71', '72'      |  4         |  b           |  Issuer                |

	/// Issuer Script Results.
	// Indicates the result of the terminal script processing.
	//            |  --       |  --              |  var.      |  b           |  Terminal              |

	/**
	 * Issuer Script Template 1.<br>
	 * Contains proprietary issuer data for transmission to the ICC before
	 * the second GENERATE AC command.
	 */
	public static final int IssuerScriptTemplate1
	               = 0x71  ; //  --              |  var.      |  b           |  Issuer                |

	/**
	 * Issuer Script Template 2.<br>
	 * Contains proprietary issuer data for transmission to the ICC after
	 * the second GENERATE AC command.
	 */
	public static final int IssuerScriptTemplate2
	               = 0x72  ; //  --              |  var.      |  b           |  Issuer                |

	/**
	 * Issuer URL.<br>
	 * The URL provides the location of the Issuer’s Library Server on the Internet.
	 */
	public static final int IssuerURL
	               = 0x5F50; //  'BF0C', '73'    |  var.      |  ans         |  ICC                   |

	/**
	 * Kernel Identifier.<br>
	 * Indicates the card's preference for the kernel on which the contactless application can be processed.
	 */
	public static final int KernelIdentifier
	               = 0x9F2A; //   --             | 1 or 3-8   |  b           |  ICC                   |

	/**
	 * Language Preference.<br>
	 * 1-4 languages stored in order of preference, each represented by 2 alphabetical
	 * characters according to ISO 639.<br>
	 * Note: EMVCo strongly recommends that cards be 
	 * 		 personalised with data element '5F2D' coded in 
	 * 		 lowercase, but that terminals accept the data 
	 * 		 element whether it is coded in upper or lower case.
	 */
	public static final int LanguagePreference
	               = 0x5F2D; //  'A5'            |  2-8       |  an 2        |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Last Online Application Transaction Counter Register -- ATC.<br>
	 * ATC value of the last transaction that went online.
	 */
	public static final int LastOnlineApplicationTransactionCounterRegister
	               = 0x9F13; //  --              |  2         |  b           |  ICC                   |

	/**
	 * Log Entry.<br>
	 * Provides the SFI of the Transaction Log file and its number of records.
	 */
	public static final int LogEntry
	               = 0x9F4D; //  'BF0C', '73'    |  2         |  b           |  ICC                   |

	/**
	 * Log Format.<br>
	 * List (in tag and length format) of data objects representing the logged data elements that are
	 * passed to the terminal when a transaction log record is read.
	 */
	public static final int LogFormat
	               = 0x9F4F; //  --              |  var.      |  b           |  ICC                   |

	/**
	 * Lower Consecutive Offline Limit.<br>
	 * Issuer-specified preference for the maximum number of consecutive offline transactions for 
	 * this ICC application allowed in a terminal with online capability.
	 */
	public static final int LowerConsecutiveOfflineLimit
	               = 0x9F14; //  '70', '77'      |  1         |  b           |  ICC                   |

	/// Maximum Target Percentage to be used for Biased Random Selection.
	// Value used in terminal risk management for random transaction selection.
	//            |  --       |  --              |  --        |  --          |  Terminal              |

	/**
	 * Merchant Category Code.<br>
	 * Classifies the type of business being done by the merchant, represented according to
	 * ISO 8583:1993 for Card Acceptor Business Code.
	 */
	public static final int MerchantCategoryCode
	               = 0x9F15; //  --              |  2         |  n 4         |  Terminal              |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Merchant Identifier.<br>
	 * When concatenated with the Acquirer Identifier, uniquely identifies a given merchant.
	 */
	public static final int MerchantIdentifier
	               = 0x9F16; //  --              |  15        |  ans 15      |  Terminal              |

	/**
	 * Merchant Name and Location.<br>
	 * Indicates the name and location of the merchant
	 */
	public static final int MerchantNameAndLocation
	               = 0x9F4E; //  --              |  var.      |  ans         |  Terminal              |

	/// Message Type.
	// Indicates whether the batch data capture record is a financial record or advice.
	//            |  --       |  --              |  1         |  n 2         |  Terminal              |

	/// Personal Identification Number (PIN) Pad Secret Key.
	// Secret key of a symmetric algorithm used by the PIN pad to encipher the PIN and by the 
	// card reader to decipher the PIN if the PIN pad and card reader are not integrated.
	//            |  --       |  --              |  --        |  --          |  Terminal              |

	/**
	 * Personal Identification Number (PIN) Try Counter.<br>
	 * Number of PIN tries remaining.
	 */
	public static final int PersonalIdentificationNumberTryCounter
	               = 0x9F17; //  --              |  1         |  b           |  ICC                   |

	/**
	 * Point-of-Service (POS) Entry Mode.<br>
	 * Indicates the method by which the PAN was entered, according to the first two digits
	 * of the ISO 8583:1987 POS Entry Mode.
	 */
	public static final int PointOfServiceEntryMode
	               = 0x9F39; //  --              |  1         |  n 2         |  Terminal              |

	/**
	 * Processing Options Data Object List -- PDOL.<br>
	 * Contains a list of terminal resident data objects (tags and lengths) needed by the ICC
	 * in processing the GET PROCESSING OPTIONS command.
	 */
	public static final int PDOL
	               = 0x9F38; //  'A5'            |  var.      |  b           |  ICC                   |

	/// Proprietary Authentication Data.
	// Contains issuer data for transmission to the card in the Issuer Authentication Data
	// of an online transaction.
	//            |  --       |  --              |  <= 8      |  b           |  Issuer                |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * READ RECORD Response Message Template.<br>
	 * Contains the contents of the record read. ( Mandatory for SFIs 1-10. Response messages
	 * for SFIs 11-30 are outside the scope of EMV, but may use template '70' ).
	 */
	public static final int ReadRecordResponseMessageTemplate
	               = 0x70  ; //  --              |  <= 252    |  var.        |  ICC                   |

	/**
	 * Response Message Template Format 1.<br>
	 * Contains the data objects (without tags and lengths)
	 * returned by the ICC in response to a command.
	 */
	public static final int ResponseMessageTemplateFormat1
	               = 0x80  ; //  --              |  var.      |  var.        |  ICC                   |

	/**
	 * Response Message Template Format 2.<br>
	 * Contains the data objects (with tags and lengths)
	 * returned by the ICC in response to a command.
	 */
	public static final int ResponseMessageTemplateFormat2
	               = 0x77  ; //  --              |  var.      |  var.        |  ICC                   |

	/**
	 * Service Code.<br>
	 * Service code as defined in ISO/IEC 7813 for track 1 and track 2.
	 */
	public static final int ServiceCode
	               = 0x5F30; //  '70', '77'      |  2         |  n 3         |  ICC                   |

	/**
	 * Short File Identifier -- SFI.<br>
	 * Identifies the AEF referenced in commands related to a given ADF or DDF. It is a binary data
	 * object having a value in the range 1 to 30 and with the three high order bits set to zero.
	 */
	public static final int ShortFileIdentifier
	               = 0x88  ; //  'A5'            |  1         |  b           |  ICC                   |

	/**
	 * Signed Dynamic Application Data.<br>
	 * Digital signature on critical application parameters for DDA or CDA.
	 */ 
	public static final int SignedDynamicApplicationData
	               = 0x9F4B; //  '77', '80'      |  NIC       |  b           |  ICC                   |

	/**
	 * Signed Static Application Data.<br>
	 * Digital signature on critical application parameters for SDA.
	 */
	public static final int SignedStaticApplicationData
	               = 0x93  ; //  '70', '77'      |  NI        |  b           |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Static Data Authentication Tag List.<br>
	 * List of tags of primitive data objects defined in this specification whose value fields
	 * are to be included in the Signed Static or Dynamic Application Data.
	 */
	public static final int StaticDataAuthenticationTagList
	               = 0x9F4A; //  '70', '77'      |  var.      |  --          |  ICC                   |

	/// Target Percentage to be Used for Random Selection.
	// Value used in terminal risk management for random transaction selection.
	//            |  --       |  --              |  --        |  --          |  Terminal              |

	/// Terminal Action Code - Default.
	// Specifies the acquirer’s conditions that cause a transaction to be rejected if it might
	// have been approved online, but the terminal is unable to process the transaction online.
	//            |  --       |  --              |  5         |  b           |  Terminal              |

	/// Terminal Action Code - Denial.
	// Specifies the acquirer’s conditions that cause the denial of a transaction
	// without attempt to go online.
	//            |  --       |  --              |  5         |  b           |  Terminal              |

	/// Terminal Action Code - Online.
	// Specifies the acquirer’s conditions that cause a transaction to be transmitted online.
	//            |  --       |  --              |  5         |  b           |  Terminal              |

	/**
	 * Terminal Capabilities.<br>
	 * Indicates the card data input, CVM, and security capabilities of the terminal.
	 */
	public static final int TerminalCapabilities
	               = 0x9F33; //  --              |  3         |  b           |  Terminal              |

	/**
	 * Terminal Country Code.<br>
	 * Indicates the country of the terminal, represented according to ISO 3166.
	 */
	public static final int TerminalCountryCode
	               = 0x9F1A; //  --              |  2         |  n 3         |  Terminal              |

	/**
	 * Terminal Floor Limit.<br>
	 * Indicates the floor limit in the terminal in conjunction with the AID.
	 */
	public static final int TerminalFloorLimit
	               = 0x9F1B; //  --              |  4         |  b           |  Terminal              |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Terminal Identification.<br>
	 * Designates the unique location of a terminal at a merchant.
	 */
	public static final int TerminalIdentification
	               = 0x9F1C; //  --              |  8         |  an 8        |  Terminal              |

	/**
	 * Terminal Risk Management Data.<br>
	 * Application-specific value used by the card for risk management purposes.
	 */
	public static final int TerminalRiskManagementData
	               = 0x9F1D; //  --              |  1-8       |  b           |  Terminal              |

	/**
	 * Terminal Type.<br>
	 * Indicates the environment of the terminal, its communications capability,
	 * and its operational control.
	 */
	public static final int TerminalType
	               = 0x9F35; //  --              |  1         |  n 2         |  Terminal              |

	/**
	 * Terminal Verification Results.<br>
	 * Status of the different functions as seen from the terminal.
	 */
	public static final int TerminalVerificationResults
	               = 0x95  ; //  --              |  5         |  b           |  Terminal              |

	/// Threshold Value for Biased Random Selection.
	// Value used in terminal risk management for random transaction selection.
	//            |  --       |  --              |  --        |  --          |  Terminal              |

	/**
	 * Track 1 Discretionary Data.<br>
	 * Discretionary part of track 1 according to ISO/IEC 7813.
	 */
	public static final int Track1DiscretionaryData
	               = 0x9F1F; //  '70', '77'      |  var.      |  ans         |  ICC                   |

	/**
	 * Track 2 Discretionary Data.<br>
	 * Discretionary part of track 2 according to ISO/IEC 7813.
	 */
	public static final int Track2DiscretionaryData
	               = 0x9F20; //  '70', '77'      |  var.      |  cn          |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Track 2 Equivalent Data.<br>
	 * Contains the data elements of track 2 according to ISO/IEC 7813, excluding start 
	 * sentinel, end sentinel, and Longitudinal Redundancy Check (LRC), as follows:<br>
	 *                                 Description                 |   Format   |<br>
	 * --------------------------------------------------------------------------<br>
	 * Primary Account Number                                      |  n, <= 19  |<br>
	 * Field Separator (Hex 'D')                                   |  b         |<br>
	 * Expiration Date (YYMM)                                      |  n 4       |<br>
	 * Service Code                                                |  n 3       |<br>
	 * Discretionary Data (defined by individual payment systems)  |  n, var.   |<br>
	 * Pad with one Hex 'F' if needed to ensure whole bytes        |  b         |<br>
	 * --------------------------------------------------------------------------<br>
	 */
	public static final int Track2EquivalentData
	               = 0x57  ; //  '70', '77'      |  <= 19     |  b           |  ICC                   |

	/// Transaction Amount.
	// Clearing amount of the transaction, including tips and other adjustments.
	//            |  --       |  --              |  6         |  n 12        |  Terminal              |

	/**
	 * Transaction Certificate Data Object List -- TDOL.<br>
	 * List of data objects (tag and length) to be used by the terminal
	 * in generating the TC Hash Value.
	 */
	public static final int TransactionCertificateDataObjectList
	               = 0x97  ; //  '70', '77'      |  <= 252    |  b           |  ICC                   |

	/**
	 * Transaction Certificate Hash Value -- TC.<br>
	 * Result of a hash function specified in Book 2, Annex B3.1.
	 */
	public static final int TransactionCertificateHashValue
	               = 0x98  ; //  --              |  20        |  b           |  Terminal              |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Transaction Currency Code.<br>
	 * Indicates the currency code of the transaction according to ISO 4217.
	 */
	public static final int TransactionCurrencyCode
	               = 0x5F2A; //  --              |  2         |  n 3         |  Terminal              |

	/**
	 * Transaction Currency Exponent.<br>
	 * Indicates the implied position of the decimal point from the right of the transaction amount 
	 * represented according to ISO 4217.
	 */
	public static final int TransactionCurrencyExponent
	               = 0x5F36; //  --              |  1         |  n 1         |  Terminal              |

	/**
	 * Transaction Date.<br>
	 * Local date that the transaction was authorised.
	 */
	public static final int TransactionDate
	               = 0x9A  ; //  --              |  3         |  n 6 YYMMDD  |  Terminal              |

	/**
	 * Transaction Personal Identification Number Data -- PIN.<br>
	 * Data entered by the cardholder for the purpose of the PIN verification.
	 */
	public static final int TransactionPersonalIdentificationNumberData
	               = 0x99  ; //  --              |  var.      |  b           |  Terminal              |

	/**
	 * Transaction Reference Currency Code.<br>
	 * Code defining the common currency used by the terminal in case the Transaction Currency 
	 * Code is different from the Application Currency Code.
	 */
	public static final int TransactionReferenceCurrencyCode
	               = 0x9F3C; //  --              |  2         |  n 3         |  Terminal              |

	/// Transaction Reference Currency Conversion.
	// CFactor used in the conversion from the Transaction Currency Code to the Transaction
	// CReference Currency Code.
	//            |  --       |  --              |  4         |  n 8         |  Terminal              |

	/**
	 * Transaction Reference Currency Exponent.<br>
	 * Indicates the implied position of the decimal point from the right of the transaction amount,
	 * with the Transaction Reference Currency Code represented according to ISO 4217.
	 */
	public static final int TransactionReferenceCurrencyExponent
	               = 0x9F3D; //  --              |  1         |  n 1         |  Terminal              |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Transaction Sequence Counter.<br>
	 * Counter maintained by the terminal that is incremented by one for each transaction.
	 */
	public static final int TransactionSequenceCounter
	               = 0x9F41; //  --              |  2-4       |  n 4-8       |  Terminal              |

	/**
	 * Transaction Status Information.<br>
	 * Indicates the functions performed in a transaction.
	 */
	public static final int TransactionStatusInformation
	               = 0x9B  ; //  --              |  2         |  b           |  Terminal              |

	/**
	 * Transaction Time.<br>
	 * Local time that the transaction was authorised.
	 */
	public static final int TransactionTime
	               = 0x9F21; //  --              |  3         |  n 6 HHMMSS  |  Terminal              |

	/**
	 * Transaction Type.<br>
	 * Indicates the type of financial transaction, represented by the first two digits of the 
	 * ISO 8583:1987 Processing Code. The actual values to be used for the Transaction Type 
	 * data element are defined by the relevant payment system.
	 */
	public static final int TransactionType
	               = 0x9C  ; //  --              |  1         |  n 2         |  Terminal              |

	/**
	 * Terminal Transaction Qualifiers.<br>
	 * The TTQ is a collection of indicators that the terminal will set to show the reader capabilities,
	 * requirements, and preferences to the card.The TTQ is only supported by certain card schemes and
	 * is only used for contactless transactions.
	 */
	public static final int TerminalTransactionQualifiers
	              = 0x9F66; //  --               |  4         |  b           |  Terminal              |

	/**
	 * Unpredictable Number.<br>
	 * Value to provide variability and uniqueness to the generation of a cryptogram.
	 */
	public static final int UnpredictableNumber
	               = 0x9F37; //  --              |  4         |  b           |  Terminal              |

	/**
	 * Upper Consecutive Offline Limit.<br>
	 * Issuer-specified preference for the maximum number of consecutive offline transactions for 
	 * this ICC application allowed in a terminal without online capability.
	 */
	public static final int UpperConsecutiveOfflineLimit
	               = 0x9F23; //  '70', '77'      |  1         |  b           |  ICC                   |

	// ------------------------------------------------------------------------------------------------
	//            |    Tag    |     Template     |   Length   |    Format    |         Source         |
	// ------------------------------------------------------------------------------------------------

	/**
	 * Payment Account Reference (PAR).<br>
	 * Payment Account Reference( PAR ) is a new data element released by EMVCo to address some of the challenges
	 * Tokenisation has introduced to the payment ecosystem whilst maintaining the current level of security provided
	 * by tokens.
	 */
	public static final int PaymentAccountReference
	               = 0x9F24; //   --             |  29        |      n       |  ICC                   |
}
