// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8;

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
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

	/**
	 * NAME.<br>
	 * .
	 */
	public static final int T
	               = 0xFFFF  ; //  1             |  n 2             |  K/ACT/DET              |

}
