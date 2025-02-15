// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8.struct;

/**
 * BerTLV Tags for data elements, defined in EMV Сontactless Book C-8, Kernel 8 Specification v1.1, Annex A. Data Dictionary
 * and NOT defined in EMV 4.4 Book 3 (see class 'TagEmv').
 */
public class TagKernel8
{
	// ----------------------------------------------------------------------------------------
	//            |    Tag    |      Length      |      Format      |         Update          |
	// ----------------------------------------------------------------------------------------

	/**
	 * A.1.24  Authenticated Application Data.<br>
	 * Returned in the response of the GENERATE AC command
	 * and contains BER-TLV-coded data which may be communicated to the issuer.
	 */
	public static final int AuthenticatedApplicationData
	               = 0x9F8106; //  <= 128        |  b               |  K/RA                   |

	/**
	 * A.1.25  Cardholder Verification Decision.<br>
	 * Indicates which cardholder verification to be performed.
	 */
	public static final int CardholderVerificationDecision
	               = 0x9F8102; //  1             |  b               |  K/RA                   |

	/**
	 * A.1.26  Card Capabilities Information.<br>
	 * Indicates the CVM and interface capabilities of the Card.
	 */
	public static final int CardCapabilitiesInformation
	               = 0x9F810D; //  2             |  b               |  K/RA                   |

	/**
	 * A.1.27  Card Data Input Capability.<br>
	 * Indicates the card data input capability of the Terminal and Reader.
	 */
	public static final int CardDataInputCapability
	               = 0x9F8206; //  1             |  b               |  K                      |

	/**
	 * A.1.28  Card Key Data.<br>
	 * Includes the x-coordinate of the ECC blinded public key point (bytes 1 to Nfield)
	 * and the encrypted blinding factor (bytes Nfield+1 to 2*Nfield)
	 * returned by the Card in the GET PROCESSING OPTIONS response.
	 */
	public static final int CardKeyData
	               = 0x9F8103; //  64, 132       |  b               |  K/RA                   |

	/**
	 * A.1.29  Card Qualifier.<br>
	 * Indicates the features supported by the Card.
	 */
	public static final int CardQualifier
	               = 0x9F2C  ; //  7             |  b               |  K/RA                   |

	// ----------------------------------------------------------------------------------------
	//            |    Tag    |      Length      |      Format      |         Update          |
	// ----------------------------------------------------------------------------------------

	/**
	 * A.1.30  Card TVR.<br>
	 * Terminal Verification Results returned by the Card in the response to the GENERATE AC command.
	 */
	public static final int CardTVR
	               = 0x9F8104; //  5             |  b               |  K/RA                   |

	/**
	 * A.1.37  CVM Capability - CVM Required.<br>
	 * Indicates the CVM capability of the Terminal and Reader to be used 
	 * when the transaction amount is greater than the Reader CVM Required Limit.
	 */
	public static final int CVMCapabilityCVMRequired
	               = 0x9F8207; //  1             |  b               |  K                      |

	/**
	 * A.1.38  CVM Capability - No CVM Required.<br>
	 * Indicates the CVM capability of the Terminal and Reader to be used 
	 * when the transaction amount is less than or equal to the Reader CVM Required Limit.
	 */
	public static final int CVMCapabilityNoCVMRequired
	               = 0x9F8208; //  1             |  b               |  K                      |

	/**
	 * A.1.40  Data Envelope 1 - 10.<br>
	 * The Data Envelopes contain proprietary information from the issuer, 
	 * payment system or third party. The Data Envelope can be retrieved 
	 * with the READ DATA command and updated with the WRITE DATA command.
	 */
	public static final int DataEnvelopeX
	               = 0x9F8110; //  <= 243        |  b               |  K/RA                   |
	public static final int DataEnvelopeMin = 0x9F8111;
	public static final int DataEnvelopeMax = 0x9F811A;

	/**
	 * A.1.41  Data Envelopes To Write.<br>
	 * Contains the Terminal data writing requests to be sent to the Card 
	 * after processing the GENERATE AC command. The value of this data 
	 * object is composed of a series of TLVs. The TLVs in Data Envelopes 
	 * To Write are coded according to the BER-TLV coding rules in section 4.7.1.
	 * This data object may be provided several times by the Terminal in a 
	 * series of DET Signals. Therefore, these values must be accumulated 
	 * in Data Envelopes To Write Yet.
	 */
	public static final int DataEnvelopesToWrite
	               = 0xBF8104; //  var.          |  b               |  K                      |

	/**
	 * A.1.43  Data Needed.<br>
	 * List of tags included in the DEK Signal to request information from the Terminal.
	 * The tags in Data Needed are coded according to the BER-TLV coding rules in section 4.7.1.
	 */
	public static final int DataNeeded
	               = 0x9F8201; //  var.          |  b               |  K                      |

	// ----------------------------------------------------------------------------------------
	//            |    Tag    |      Length      |      Format      |         Update          |
	// ----------------------------------------------------------------------------------------

	/**
	 * A.1.44  Data Record.<br>
	 * A list of TLV-coded data objects returned in the OUT Signal on the 
	 * completion of transaction processing. The Data Record contains the 
	 * necessary data objects for authorisation and clearing as shown in Table A.11.
	 */
	public static final int DataRecord
	               = 0xBF8102; //  var.          |  b               |  K                      |

	/**
	 * A.1.45  DataToSend.<br>
	 * A list of TLV-coded data objects that contains the accumulated data 
	 * sent by the Kernel to the Terminal in a DEK Signal.
	 * These data objects may correspond to Terminal reading requests, 
	 * obtained from the Card by means of READ DATA or READ RECORD commands,
	 * or may correspond to data that the Kernel posts to the Terminal as part of its own processing.
	 */
	public static final int DataToSend
	               = 0xBF8101; //  var.          |  b               |  K                      |

	/**
	 * A.1.46  Default CDOL1.<br>
	 * The default value for CDOL1 that the Kernel uses to construct the 
	 * value field of the GENERATE AC command when the Card does not return a CDOL1.
	 */
	public static final int DefaultCDOL1
	               = 0x9F8220; //  <= 250        |  b               |  K                      |

	/**
	 * A.1.47  Default IAD MAC Offset.<br>
	 * The default offset of the Issuer Application Data MAC in Issuer 
	 * Application Data when 'Copy IAD MAC in IAD' in Application 
	 * Interchange Profile indicates that the Default IAD MAC Offset must be used.
	 * The offset is zero-based.
	 */
	public static final int DefaultIADMACOffset
	               = 0x9F821E; //  1             |  b               |  K                      |

	/**
	 * A.1.51  Discretionary Data Tag List.<br>
	 * Contains a list of tags of data objects to be included in the 
	 * Discretionary Data.
	 */
	public static final int DiscretionaryDataTagList
	               = 0x9F821F; //  var.          |  b               |  K                      |

	/**
	 * A.1.52  Discretionary Data.<br>
	 * A TLV-coded list of Kernel-specific data objects sent to the Terminal 
	 * as a separate field in the OUT Signal and includes the data objects of 
	 * which the tags are listed in Discretionary Data Tag List.
	 */
	public static final int DiscretionaryData
	               = 0xBF8103; //  var.          |  b               |  K                      |

	// ----------------------------------------------------------------------------------------
	//            |    Tag    |      Length      |      Format      |         Update          |
	// ----------------------------------------------------------------------------------------

	/**
	 * A.1.54  Enhanced Data Authentication MAC.<br>
	 * A MAC over the Application Cryptogram and Issuer Application Data MAC.
	 */
	public static final int EDA_MAC
	               = 0x9F8105; //  8             |  b               |  K/RA                   |

	/**
	 * A.1.55  Error Indication.<br>
	 * Contains information regarding the nature of the error that has been 
	 * encountered during the transaction processing.
	 * This data object should be part of the Discretionary Data.
	 */
	public static final int ErrorIndication
	               = 0x9F8204; //  6             |  b               |  K                      |

	/**
	 * A.1.56  Extended SDA Tag List.<br>
	 * Contains a list of the tags of data objects to be included
	 * in the Static Data To Be Authenticated.
	 */
	public static final int ExtendedSDATagList
	               = 0x9F810A; //  var.          |  b               |  K/RA                   |

	/**
	 * A.1.62  Hold Time Value.<br>
	 * Indicates the time that the field is to be turned off after the transaction
	 * is completed if requested to do so by the Card. The Hold Time Value is in units of 100ms.
	 */
	public static final int HoldTimeValue
	               = 0x9F8212; //  1             |  b               |  K                      |

	/**
	 * A.1.63  IAD MAC Offset.<br>
	 * Indicates the offset of the Issuer Application Data MAC in Issuer Application Data
	 * when 'Copy IAD MAC in IAD' in Application Interchange Profile
	 * indicates that the IAD MAC Offset must be used.
	 * The offset is zero-based.
	 */
	public static final int IAD_MACOffset
	               = 0x9F8107; //  1             |  b               |  K/RA                   |

	/**
	 * A.1.64  ICC ECC Public Key (for RSA Certificates).<br>
	 * The ICC ECC Public Key (x-coordinate of ICC ECC Public Key point) 
	 * is returned in a record referenced in the AFL in case RSA certificates are used.
	 */
	public static final int ICCECCPublicKey_RSACert
	               = 0x9F810B; //  32, 66        |  b               |  K/RA                   |

	/**
	 * A.1.70  Issuer Application Data MAC.<br>
	 * A MAC over static card data and transaction related data.
	 * The Issuer Application Data MAC may be copied by the Kernel in the 
	 * Issuer Application Data as indicated by 'Copy IAD MAC in IAD' in Application Interchange Profile.
	 */
	public static final int IAD_MAC
	               = 0x9F8109; //  8             |  b               |  K                      |

	// ----------------------------------------------------------------------------------------
	//            |    Tag    |      Length      |      Format      |         Update          |
	// ----------------------------------------------------------------------------------------

	/**
	 * A.1.77  Kernel Configuration.<br>
	 * Indicates the Kernel Configuration Options.
	 */
	public static final int KernelConfiguration
	               = 0x9F8209; //  2             |  b               |  K                      |

	/**
	 * A.1.79  Kernel Key Data.<br>
	 * Used to transfer the (x, y) coordinates of the ephemeral kernel public 
	 * key to the Card in the value field of the GET PROCESSING OPTIONS command.
	 */
	public static final int KernelKeyData
	               = 0x9E    ; //  <= 132        |  b               |  K                      |

	/**
	 * A.1.80  Kernel Qualifier.<br>
	 * Indicates to the Card any Kernel specific data that it needs to communicate.
	 * Kernel Qualifier is built by the Kernel with data from different configuration data objects.
	 */
	public static final int KernelQualifier
	               = 0x9F2B  ; //  8             |  b               |  K                      |

	/**
	 * A.1.81  Kernel Reserved TVR Mask.<br>
	 * Determines which bits in the Terminal Verification Results cannot be 
	 * altered by the Card TVR returned by the Card in the response to the 
	 * GENERATE AC command. The bits set to 1b cannot be altered by the Card.
	 */
	public static final int KernelReservedTVRMask
	               = 0x9F821A; //  5             |  b               |  K                      |

	/**
	 * A.1.85  Maximum Relay Resistance Grace Period.<br>
	 * The Minimum Relay Resistance Grace Period and Maximum Relay Resistance Grace Period
	 * represent how far outside the window defined by the Card that the measured time may be
	 * and yet still be considered acceptable. The Maximum Relay Resistance Grace Period
	 * is expressed in units of hundreds of microseconds.
	 */
	public static final int MaximumRRGracePeriod
	               = 0x9F8214; //  2             |  b               |  K                      |

	/**
	 * A.1.91  Message Hold Time.<br>
	 * Indicates the default delay for the processing of the next MSG Signal.
	 * The Message Hold Time is an integer in units of 100ms.
	 */
	public static final int MessageHoldTime
	               = 0x9F8211; //  3             |  n 6             |  K                      |

	// ----------------------------------------------------------------------------------------
	//            |    Tag    |      Length      |      Format      |         Update          |
	// ----------------------------------------------------------------------------------------

	/**
	 * A.1.93  Message Identifiers On Restart.<br>
	 * The Message Identifiers On Restart is a configuration data object that defines
	 * the message identifiers that can be used by the Card in 'Message Identifier'
	 * in Restart Indicator. Each byte of the data object contains one message identifier
	 * as shown in Table A.21. Message Identifiers On Restart must only contain message identifiers 
	 * that are supported by Process D.
	 */
	public static final int MessageIdentifiersOnRestart
	               = 0x9F821D; //  <= 32         |  b               |  K                      |

	/**
	 * A.1.95  Minimum Relay Resistance Grace Period.<br>
	 * The Minimum Relay Resistance Grace Period and Maximum Relay Resistance Grace Period
	 * represent how far outside the window defined by the Card
	 * that the measured time may be and yet still be considered acceptable.
	 * The Minimum Relay Resistance Grace Period is expressed in units of hundreds of microseconds.
	 */
	public static final int MinimumRelayResistanceGracePeriod
	               = 0x9F8213; //  2             |  b               |  K                      |

	/**
	 * A.1.98  Outcome Parameter Set.<br>
	 * Used to indicate to the Terminal the outcome of the transaction processing by the Kernel.
	 * Its value is an accumulation of results about applicable parts of the transaction.
	 */
	public static final int OutcomeParameterSet
	               = 0x9F8210; //  8             |  b               |  K                      |

	/**
	 * A.1.103  Proceed To First Write Flag.<br>
	 * Indicates that the Terminal will send no more requests to read data 
	 * other than as indicated in Tags To Read. This data item indicates the 
	 * point at which the Kernel shifts from the Card reading phase to the Card writing phase.
	 */
	public static final int ProceedToFirstWriteFlag
	               = 0x9F8202; //  1             |  b               |  K/ACT/DET              |

	/**
	 * A.1.104  Reader Contactless Floor Limit.<br>
	 * Indicates the transaction amount above which transactions must be authorised online.
	 */
	public static final int ReaderContactlessFloorLimit
	               = 0x9F820D; //  6             |  n 12            |  K                      |

	/**
	 * A.1.105  Reader CVM Required Limit.<br>
	 * Indicates the transaction amount above which the Kernel instantiates 
	 * the CVM capabilities field in Terminal Capabilities with CVM Capability - CVM Required.
	 */
	public static final int ReaderCVMRequiredLimit
	               = 0x9F820E; //  6             |  n 12            |  K                      |

	// ----------------------------------------------------------------------------------------
	//            |    Tag    |      Length      |      Format      |         Update          |
	// ----------------------------------------------------------------------------------------

	/**
	 * A.1.106  Read Data Status.<br>
	 * Information reported by the Kernel to the Terminal, about the processing of READ DATA commands.
	 * Possible values are 'completed' or 'not completed'. In the latter case, 
	 * this status is not specific about which of the READ DATA commands failed,
	 * or about how many of these commands have failed or succeeded.
	 * This data object is part of the Discretionary Data provided by the Kernel to the Terminal.
	 */
	public static final int ReadDataStatus
	               = 0x9F821C; //  1             |  b               |  K                      |

	/**
	 * A.1.109  Relay Resistance Accuracy Threshold.<br>
	 * Represents the threshold above which the Kernel considers the variation between
	 * Measured Relay Resistance Processing Time and Min Time For Processing Relay Resistance APDU
	 * no longer acceptable. The Relay Resistance Accuracy Threshold is expressed 
	 * in units of hundreds of microseconds.
	 */
	public static final int RR_AccuracyThreshold
	               = 0x9F8217; //  2             |  b               |  K                      |

	/**
	 * A.1.110  Relay Resistance Time Excess.<br>
	 * Contains the excess time on top of the Max Time For Processing Relay Resistance APDU
	 * used by the card to process the EXCHANGE RELAY RESISTANCE DATA command.
	 * The Relay Resistance Time Excess is expressed in units of hundreds of microseconds.
	 */
	public static final int RR_TimeExcess
	               = 0x9F810C; //  2             |  b               |  K                      |

	/**
	 * A.1.111  Relay Resistance Transmission Time Mismatch Threshold.<br>
	 * Represents the threshold above which the Kernel considers the variation between
	 * Device Estimated Transmission Time For Relay Resistance R-APDU and
	 * Terminal Expected Transmission Time For Relay Resistance R-APDU no longer acceptable.
	 * The Relay Resistance Transmission Time Mismatch Threshold is a percentage 
	 * and expressed as an integer.
	 */
	public static final int RR_TransmissionTimeMismatchThreshold
	               = 0x9F8218; //  2             |  b               |  K                      |

	/**
	 * A.1.113  Restart Indicator.<br>
	 * Indicator returned by the Card that comprises two fields: an indication 
	 * that restart is needed and a message indicator.
	 */
	public static final int RestartIndicator
	               = 0x9F8108; //  2-5           |  b               |  K/RA                   |

	// ----------------------------------------------------------------------------------------
	//            |    Tag    |      Length      |      Format      |         Update          |
	// ----------------------------------------------------------------------------------------

	/**
	 * A.1.115  Security Capability.<br>
	 * Indicates the security capability of the Kernel (Table A.27).
	 */
	public static final int SecurityCapability
	               = 0x9F820A; //  1             |  b               |  K                      |

	/**
	 * A.1.118  Tag Mapping List.<br>
	 * List of tags for which the Kernel will use a mapped tag to populate the 
	 * Data Record and Discretionary Data. The tags in the Tag Mapping List 
	 * are coded according to the BER-TLV coding rules in section 4.7.1. 
	 * The tags in the Tag Mapping List are ordered in pairs of two tags: 
	 * { Tag1 MappedTag1 Tag2 MappedTag2 … Tagn  MappedTagn }.
	 */
	public static final int TagMappingList
	               = 0x9F8221; //  var.          |  b               |  K                      |

	/**
	 * A.1.119  Tags To Read.<br>
	 * List of tags indicating the data the Terminal has requested to be read. 
	 * The tags in Tags To Read are coded according to the BER-TLV
	 * coding rules in section 4.7.1.
	 * This data object is present if the Terminal wants any data back from 
	 * the Card before the Data Record. This could be in the context of data 
	 * storage, or for non data storage usage reasons, for example the PAN.
	 * This data object may contain configured data.
	 * This data object may be provided several times by the Terminal. 
	 * Therefore, the values of each of these tags must be accumulated in 
	 * the Tags To Read Yet buffer.
	 */
	public static final int TagsToRead
	               = 0x9F8203; //  var.          |  b               |  K/ACT/DET              |

	/**
	 * A.1.121  Terminal Action Code - Denial.<br>
	 * Specifies the acquirer's conditions that cause the denial of a transaction
	 * without attempting to go online.
	 */
	public static final int TerminalActionCodeDenial
	               = 0x9F820B; //  5             |  b               |  K                      |

	/**
	 * A.1.122  Terminal Action Code - Online.<br>
	 * Specifies the acquirer's conditions that cause a transaction
	 * to be transmitted online on an online capable Terminal.
	 */
	public static final int TerminalActionCodeOnline
	               = 0x9F820C; //  5             |  b               |  K                      |

	// ----------------------------------------------------------------------------------------
	//            |    Tag    |      Length      |      Format      |         Update          |
	// ----------------------------------------------------------------------------------------

	/**
	 * A.1.125  Terminal Expected Transmission Time For Relay Resistance C-APDU.<br>
	 * Represents the time that the Kernel expects to need for transmitting 
	 * the EXCHANGE RELAY RESISTANCE DATA command to the Card.
	 * The Terminal Expected Transmission Time For Relay Resistance 
	 * C-APDU is expressed in units of hundreds of microseconds.
	 */
	public static final int TerminalExpectedTimeForRRCAPDU
	               = 0x9F8215; //  2             |  b               |  K                      |

	/**
	 * A.1.126  Terminal Expected Transmission Time For Relay Resistance R-APDU.<br>
	 * Represents the time that the Kernel expects that the Card will need for 
	 * transmitting the EXCHANGE RELAY RESISTANCE DATA R-APDU.
	 * The Terminal Expected Transmission Time For Relay Resistance 
	 * R-APDU is expressed in units of hundreds of microseconds.
	 */
	public static final int TerminalExpectedTimeForRRRAPDU
	               = 0x9F8216; //  2             |  b               |  K                      |

	/**
	 * A.1.132  Timeout Value.<br>
	 * Defines the time in ms before the timer generates a TIMEOUT Signal.
	 */
	public static final int TimeoutValue
	               = 0x9F820F; //  2             |  b               |  K                      |

	/**
	 * A.1.143  User Interface Request Data 1.<br>
	 * The TLV Database of the Kernel includes two UIRDs: User Interface 
	 * Request Data 1 and User Interface Request Data 2. A UIRD combines 
	 * all user interface request parameters to be sent with the OUT Signal or MSG Signal.
	 * User Interface Request Data 1 is included in the OUT Signal if at least 
	 * one of the flags 'UI Request on Outcome Present' or 'UI Request on 
	 * Restart Present' is set. If both flags are set, then User Interface 
	 * Request Data 1 includes the user interface request parameters to be 
	 * acted upon as the outcome is processed.
	 * User Interface Request Data 2 is only included in the OUT Signal if 
	 * both flags 'UI Request on Outcome Present' and 'UI Request on 
	 * Restart Present' in Outcome Parameter Set are set. In this case, User 
	 * Interface Request Data 2 includes the user interface request 
	 * parameters to be acted upon at the restart of the transaction.
	 */
	public static final int UserInterfaceRequestData1
	               = 0x9F8205; //  13            |  b               |  K                      |

	/**
	 * A.1.144  User Interface Request Data 2.<br>
	 * Refer to description of User Interface Request Data 1.
	 */
	public static final int UserInterfaceRequestData2
	               = 0x9F8219; //  13            |  b               |  K                      |

	/**
	 * A.1.145  Write Data Status.<br>
	 * Information reported by the Kernel to the Terminal, about the processing of WRITE DATA commands.
	 * Possible values are 'completed' or 'not completed'. In the latter case, 
	 * this status is not specific about which of the WRITE DATA commands 
	 * failed, or about how many of these commands have failed or succeeded.
	 * This data object is part of the Discretionary Data provided by the Kernel to the Terminal.
	 */
	public static final int WriteDataStatus
	               = 0x9F821B; //  1             |  b               |  K                      |

	// ----------------------------------------------------------------------------------------
	//            |    Tag    |      Length      |      Format      |         Update          |
	// ----------------------------------------------------------------------------------------
}
