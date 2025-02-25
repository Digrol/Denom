// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.format.*;
import org.denom.crypt.AES;
import org.denom.crypt.ec.ECAlg;
import org.denom.crypt.ec.Fp.custom.Secp256r1;
import org.denom.crypt.hash.SHA256;
import org.denom.smartcard.*;
import org.denom.smartcard.emv.*;
import org.denom.smartcard.emv.certificate.IccEccCertificate;
import org.denom.smartcard.emv.certificate.IssuerEccCertificate;
import org.denom.smartcard.emv.kernel8.struct.*;

import static org.denom.Binary.*;
import static org.denom.Ex.*;
import static org.denom.format.BerTLV.Tlv;

/**
 * Терминал с единственным ядром - Kernel8 и выбором только одного приложения по AID.
 * Алгоритмы соответствуют Book C-8, отдельные процессы не выделялись, вместо сигналов - прямые вызовы методов
 * для упрощения реализации.
 * По сути здесь то, что делают процессы K, S, P.
 */
public class TerminalKernel8
{
	private final static int COLOR_KERNEL8 = 0xFF5295FE;

	private final CardReader cr;
	private final ILog log;

	private Random algRandom;

	private Map<Integer, Binary> caPublicKeys = new LinkedHashMap<>();

	private TagDictKernel8 dict = new TagDictKernel8();

	/**
	 * Конфигурация терминала и ядра
	 */
	private TlvDatabase config;

	private boolean sessionStarted = false;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * TLV-объекты на время одной сессии.
	 */
	public TlvDatabase tlvDB;

	// =================================================================================================================
	// Сессионные переменные
	// =================================================================================================================

	/**
	 * [8 байт] - поле value для TLV Outcome Parameter Set (tag 9F8210).
	 */
	private OutcomeParameterSet outcomeParameterSet = new OutcomeParameterSet();
	private UIRD uird1 = new UIRD();
	private UIRD uird2 = new UIRD();
	private ErrorIndication errorIndication = new ErrorIndication();

	private int rrpCounter;

	// -----------------------------------------------------------------------------------------------------------------
	private static final int KERNEL_DECISION_DECLINE = 0b00_000000; // 0x00
	private static final int KERNEL_DECISION_ACCEPT  = 0b01_000000; // 0x40
	private static final int KERNEL_DECISION_ONLINE  = 0b10_000000; // 0x80

	private int kernelDecision; // [1 байт]

	// =================================================================================================================
	// Сессионные переменные для криптографии - Process C
	// =================================================================================================================

	// Terminal ephimeral key pair.
	private ECAlg ecDk;

	private int ECNField;

	// Blinded ICC Public Key
	private Binary Pc;

	private Binary rRecovered;

	// Kernel Message Counter
	private Int KMC = new Int(0);
	// Card Message Counter
	private Int CMC = new Int(0);

	private AES aesSKc;
	private AES aesSKi;

	private Binary signedRecords;

	private Binary pdolValues;
	private Binary cdolRelData;
	private Binary extendedSDARelData;

	private Binary lastERRDResponse;

	private Binary iadMac;

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalKernel8( JSONObject joTerminalConfig, CardReader cr, ILog log, Random rand )
	{
		MUST( (cr != null) && (log != null) && (joTerminalConfig != null), "Null params for POS Terminal" );

		this.cr = cr;
		this.log = log;
		this.algRandom = rand;

		setConfig( joTerminalConfig );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать параметры терминала и ядра.
	 * Все обязательные теги из Table A.38 должны быть заданы здесь или в параметрах сессии,
	 * иначе будет исключение при попытке выполнить транзакцию.
	 */
	public void setConfig( JSONObject jo )
	{
		config = new TlvDatabase( new TagDictKernel8() );

		Iterator<String> keys = jo.keys();
		while( keys.hasNext() )
		{
			String key = keys.next();
			Binary val = jo.getBinary( key );
			TagInfo tagInfo = dict.find( key );
			if( tagInfo == null )
			{
				THROW( "Unknown POS terminal param: " + key );
			}
			else
			{
				MUST( tagInfo.isGoodLen( val ), "Wrong length: " + key );
				config.store( tagInfo.tag, val );
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void addCAPublicKey( int caPKIndex, final Binary caPublicKey )
	{
		caPublicKeys.put( caPKIndex, caPublicKey );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkParamPresent( int tag )
	{
		if( !tlvDB.IsPresent( tag ) )
			THROW( "Tag " + Binary.Num_Bin( tag, 0 ).Hex() + " (" + dict.find( tag ).name + ") is absent in POS terminal parameters" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверяем наличие обязательных параметров терминала.
	 * Book C-8, A.3  Configuration Data Objects
	 */
	private void checkMandatoryParams()
	{
		checkParamPresent( TagEmv.AdditionalTerminalCapabilities );
		checkParamPresent( TagEmv.ApplicationIdentifierTerminal );
		checkParamPresent( TagEmv.ApplicationVersionNumberTerminal );
		checkParamPresent( TagKernel8.CardDataInputCapability );
		checkParamPresent( TagKernel8.CVMCapabilityCVMRequired );
		checkParamPresent( TagKernel8.CVMCapabilityNoCVMRequired );
		checkParamPresent( TagKernel8.DefaultIADMACOffset );
		checkParamPresent( TagKernel8.DiscretionaryDataTagList );
		checkParamPresent( TagKernel8.HoldTimeValue );
		checkParamPresent( TagKernel8.KernelConfiguration );
		checkParamPresent( TagKernel8.KernelReservedTVRMask );
		checkParamPresent( TagKernel8.MaximumRRGracePeriod );
		checkParamPresent( TagKernel8.MessageHoldTime );
		checkParamPresent( TagKernel8.MessageIdentifiersOnRestart );
		checkParamPresent( TagKernel8.MinimumRRGracePeriod );
		checkParamPresent( TagKernel8.ReaderContactlessFloorLimit );
		checkParamPresent( TagKernel8.ReaderCVMRequiredLimit );
		checkParamPresent( TagKernel8.RR_AccuracyThreshold );
		checkParamPresent( TagKernel8.RR_TransmissionTimeMismatchThreshold );
		checkParamPresent( TagKernel8.SecurityCapability );
		checkParamPresent( TagKernel8.TagMappingList );
		checkParamPresent( TagKernel8.TerminalActionCodeDenial );
		checkParamPresent( TagKernel8.TerminalActionCodeOnline );
		checkParamPresent( TagEmv.TerminalCountryCode );
		checkParamPresent( TagKernel8.TerminalExpectedTimeForRRCAPDU );
		checkParamPresent( TagKernel8.TerminalExpectedTimeForRRRAPDU );
		checkParamPresent( TagEmv.TerminalRiskManagementData );
		checkParamPresent( TagEmv.TerminalType );
		checkParamPresent( TagKernel8.TimeoutValue );
		checkParamPresent( TagEmv.TransactionType );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param uird1 может быть null
	 * @param uird2 может быть null
	 */
	private OUT createOUT( boolean isDataRecord, UIRD uird1, UIRD uird2 )
	{
		tlvDB.store( TagKernel8.ErrorIndication, errorIndication.toBin() );
		return new OUT( tlvDB, outcomeParameterSet, isDataRecord, uird1, uird2 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Outcome Parameter Set,  Discretionary Data.
	 * @param uird1 может быть null.
	 */
	private OUT createOUT( UIRD uird1 )
	{
		return createOUT( false, uird1, null );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void kernel8Start( TlvDatabase termParamsForSession )
	{
		// KS.1
		tlvDB = config.clone();
		tlvDB.append( termParamsForSession );

		// KS.2
		outcomeParameterSet = new OutcomeParameterSet();
		outcomeParameterSet.onInitKernel8();

		uird1 = new UIRD();
		uird1.holdTime = tlvDB.GetValue( TagKernel8.MessageHoldTime );

		uird2 = new UIRD();

		errorIndication = new ErrorIndication();
		errorIndication.msgOnError = MessageIdentifier.Error_OtherCard;

		// KS.3, KS.4. Если необходимые теги не заданы в конфигурации и параметрах сессии, то исключение, а не OUT.
		checkMandatoryParams();

		log.writeln( COLOR_KERNEL8, "Kernel started" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary selectApplication()
	{
		Binary appAid = tlvDB.GetValue( TagEmv.ApplicationIdentifierTerminal );

		cr.Cmd( ApduIso.SelectAID( appAid ), RApdu.ST_ANY );
		MUST( cr.rapdu.isOk() || (cr.rapdu.sw1() == 0x62) || (cr.rapdu.sw1() == 0x63),
			"Can't select card application, status: " + Num_Bin( cr.rapdu.status, 2 ).Hex() );

		return cr.resp;
	}

	// -----------------------------------------------------------------------------------------------------------------
	// 1.5
	private boolean parseFCITemplate( Binary fci )
	{
		if( !BerTLV.isTLV( fci ) )
			return false;

		BerTLV tlv = new BerTLV( fci );
		if( tlv.tag != TagEmv.FCI )
			return false;

		// Save whole FCI
		tlvDB.store( tlv );

		// And primitive tags in it
		if( !tlvDB.ParseAndStoreCardResponse( fci ) )
			return false;

		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void setTVRBit( long bit )
	{
		long tvr = tlvDB.GetRef( TagEmv.TerminalVerificationResults ).asNum();
		tvr |= bit;
		tlvDB.store( TagEmv.TerminalVerificationResults, Num_Bin( tvr, 5 ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void setTRMDBit( long bit )
	{
		long tvr = tlvDB.GetRef( TagEmv.TerminalRiskManagementData ).asNum();
		tvr |= bit;
		tlvDB.store( TagEmv.TerminalRiskManagementData, Num_Bin( tvr, 8 ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param SCAsiList [3 байта]
	 */
	private void processC_Init( final Binary SCAsiList, boolean rsaSupported )
	{
		// C.100
		// Поддерживается только один Algorithm Suite for SecureChannel
		int scASI = 0xFF;
		for( int i = 0; i < SCAsiList.size(); ++i )
		{
			if( SCAsiList.get( i ) == 0x00 )
				scASI = 0x00;
		}

		// C.101
		if( scASI == 0xFF )
		{
			// 2.3
			errorIndication.L2 = ErrorIndication.L2_CARD_DATA_ERROR;
			// 2.4
			uird1.messageId = MessageIdentifier.Error_OtherCard;
			uird1.status = UIRD.STATUS_NOT_READY;
			// 2.5
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_END_APPLICATION );
			outcomeParameterSet.setStart( OutcomeParameterSet.START_NA );
			outcomeParameterSet.setB5Bit( OutcomeParameterSet.BIT_UI_REQUEST_ON_OUTCOME );
			throw createOUT( uird1 );
		}

		// C.102
		Secp256r1 curve = new Secp256r1();
		ecDk = new ECAlg( curve, algRandom );
		ecDk.generateKeyPair();
		ECNField = curve.getNField();

		// C.10
		KMC = new Int( 0x0000 );
		CMC = new Int( 0x8000 );

		signedRecords = Bin();

		Binary CAsiList;
		if( rsaSupported )
			CAsiList = Bin( "0110FF" );
		else
			CAsiList = Bin( "10FFFF" );

		// C.103, 2.1

		// 2.6
		Binary kernelQualifier = tlvDB.GetRef( TagKernel8.KernelQualifier );
		kernelQualifier.set( 2, scASI );
		kernelQualifier.set( 3, CAsiList, 0, CAsiList.size() );

		// 2.7
		Binary Qk = ecDk.getPublic( false );
		Qk = Qk.last( Qk.size()-1 );
		tlvDB.store( TagKernel8.KernelKeyData, Qk );

		log.writeln( COLOR_KERNEL8, "Process C initialized" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void initOnSelectApp( final Binary fci )
	{
		// 1.5
		boolean ok = parseFCITemplate( fci );
		if( !ok )
		{
			// 1.7
			errorIndication.L2 = ErrorIndication.L2_PARSING_ERROR;
			errorIndication.msgOnError = MessageIdentifier.NA;
		}

		// 1.8
		if( ok && !(tlvDB.IsNotEmpty( TagEmv.DFName ) && tlvDB.IsNotEmpty( TagKernel8.CardQualifier )
				&& (tlvDB.GetValue( TagKernel8.CardQualifier ).get( 0 ) != 0 )) )
		{
			errorIndication.L2 = ErrorIndication.L2_CARD_DATA_MISSING;
			errorIndication.msgOnError = MessageIdentifier.NA;
			ok = false;
		}

		if( !ok )
		{
			// 1.14
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_SELECT_NEXT );
			outcomeParameterSet.setStart( OutcomeParameterSet.START_C );
			throw createOUT( null );
		}

		// 1.10
		if( tlvDB.IsNotEmpty( TagEmv.LanguagePreference ) )
		{
			Binary langPref = tlvDB.GetValue( TagEmv.LanguagePreference );
			langPref.resize( 8 );
			uird1.languagePref = langPref;
			uird2.languagePref = langPref.clone();
		}

		// 1.11
		// IF ['Support for field off detection' in Card Qualifier is set]
		if( (tlvDB.GetValue( TagKernel8.CardQualifier ).get( 4 ) & 0x80) != 0 )
			outcomeParameterSet.setFieldOffRequest( tlvDB.GetValue( TagKernel8.HoldTimeValue ).get( 0 ) );

		// 1.13
		tlvDB.store( TagEmv.CVMResults, Bin( "000000" ) );

		kernelDecision = KERNEL_DECISION_ACCEPT;

		Binary tvr = Bin( 5 );
		tlvDB.store( TagEmv.TerminalVerificationResults, tvr );
		setTVRBit( TVR.Kernel8ProcessingAndTVRFormat );


		Binary terminalCapabilities = Bin( 3 );
		terminalCapabilities.set( 0, tlvDB.GetValue( TagKernel8.CardDataInputCapability ).get( 0 ) );
		terminalCapabilities.set( 2, tlvDB.GetValue( TagKernel8.SecurityCapability ).get( 0 ) );
		tlvDB.store( TagEmv.TerminalCapabilities, terminalCapabilities );

		rrpCounter = 0;

		tlvDB.store( TagKernel8.RR_TimeExcess, Bin("0000") );

		Binary kernelQualifier = Bin("02 00 00 00  00 00 00 00");
		// 'Local authentication enabled' from terminalCapabilities to kernelQualifier
		if( terminalCapabilities.getBit( 2, 4 ) )
			kernelQualifier.setBit( 1, 7 );
		tlvDB.store( TagKernel8.KernelQualifier, kernelQualifier );

		Binary unpredictableNumber = Bin().random( algRandom, 4 );
		tlvDB.store( TagEmv.UnpredictableNumber, unpredictableNumber );

		// Не используются в однопроцессной реализации
		// Crypto Read Data Counter := '00'
		// Crypto Read Record Counter := '00'

		tlvDB.store( TagKernel8.ReadDataStatus, Bin("80") );
		tlvDB.store( TagKernel8.WriteDataStatus, Bin("00") );

		// Не используются в данной реализации,
		// т.к. Read Data и Write Data пользователь этого класса делает прямыми вызовами методов:
		// Data Needed
		// Data To Send
		// Tags To Read Yet
		// Read Data Tags To Validate Yet
		// Data Envelopes To Write Yet

		boolean isRSAEnabled = tlvDB.GetValue( TagKernel8.KernelConfiguration ).getBit( 0, 5 );

		//  Kernel8 - RSA certs not supported
		if( isRSAEnabled )
		{
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_END_APPLICATION );
			errorIndication.L2 = ErrorIndication.L2_TERMINAL_DATA_ERROR;
			throw createOUT( null );
		}

		processC_Init( tlvDB.GetValue( TagKernel8.CardQualifier ).slice( 1, 3 ), isRSAEnabled );
	}

	// -----------------------------------------------------------------------------------------------------------------
	// S202122232425 - E
	private void S202122232425_E()
	{
		// 202122232425.24
		uird1.messageId = MessageIdentifier.Error_OtherCard;
		uird1.status = UIRD.STATUS_NOT_READY;

		// 202122232425.25
		outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_END_APPLICATION );
		outcomeParameterSet.setB5Bit( OutcomeParameterSet.BIT_UI_REQUEST_ON_OUTCOME );
		outcomeParameterSet.setStart( OutcomeParameterSet.START_NA );

		throw createOUT( uird1 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void parsingError()
	{
		errorIndication.L2 = ErrorIndication.L2_PARSING_ERROR;
		S202122232425_E();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void statusError( int status )
	{
		errorIndication.L2 = ErrorIndication.L2_STATUS_BYTES;
		errorIndication.SW12 = status;
		S202122232425_E();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private boolean processC_gpoPrivacy( final Binary cardKeyData )
	{
		// C.11
		if( cardKeyData.size() != (ECNField * 2) )
			return false;

		Pc = cardKeyData.first( ECNField );

		try
		{
			Binary SKcSKi = EmvCrypt.BDHCalcSessionKeys( ecDk, Pc );
			Binary SKc = SKcSKi.first( 16 );
			Binary SKi = SKcSKi.last( 16 );

			aesSKc = new AES( SKc );
			aesSKi = new AES( SKi );

			Binary encryptedR = cardKeyData.last( ECNField );
			rRecovered = EmvCrypt.BDHRecoverR( aesSKc, encryptedR, CMC );

			log.writeln( COLOR_KERNEL8, "Session keys generated" );
		}
		catch (Throwable ex)
		{
			return false;
		}

		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void getProcessingOptions()
	{
		// Search PDOL in tlvDB and form PDOL Values (without tag 0x83)

		// 2.15
		if( tlvDB.IsNotEmpty( TagEmv.PDOL ) )
			// 2.16
			pdolValues = tlvDB.formDOLValues( tlvDB.GetValue( TagEmv.PDOL ) );
		else
			// 2.18
			pdolValues = Bin();


		// 2.20, 2.21 - CMD GET PROCESSING OPTIONS
		cr.Cmd( ApduEmv.GetProcessingOptions( pdolValues ), RApdu.ST_ANY );


		// S.20,  20.10
		if( cr.rapdu.status != 0x9000 )
		{
			// 20.11
			errorIndication.L2 = ErrorIndication.L2_STATUS_BYTES;
			errorIndication.SW12 = cr.rapdu.status;
			errorIndication.msgOnError = MessageIdentifier.NA;

			// 20.12
			outcomeParameterSet.setFieldOffRequest( 0xFF );
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_SELECT_NEXT );
			outcomeParameterSet.setStart( OutcomeParameterSet.START_C );
			throw createOUT( null );
		}

		// 20.13
		Binary gpoResp = cr.resp;

		// 20.14
		boolean parseOk = tlvDB.ParseAndStoreCardResponse( gpoResp );
		if( (gpoResp.size() < 2) || (gpoResp.get( 0 ) != TagEmv.ResponseMessageTemplateFormat2) || !parseOk )
			parsingError();


		// 20.18
		boolean ok = tlvDB.IsNotEmpty( TagEmv.AFL );
		ok &= tlvDB.IsNotEmpty( TagEmv.AIP );
		ok &= tlvDB.IsNotEmpty( TagKernel8.CardKeyData );
		ok &= (tlvDB.IsNotEmpty( TagEmv.CDOL1 ) || tlvDB.IsNotEmpty( TagKernel8.DefaultCDOL1 ));
		if( !ok )
		{
			// 20.19
			errorIndication.L2 = ErrorIndication.L2_CARD_DATA_MISSING;
			S202122232425_E();
		}

		// 20.20
		if( !tlvDB.IsNotEmpty( TagEmv.CDOL1 ) )
			// 20.21
			tlvDB.store( TagEmv.CDOL1, tlvDB.GetValue( TagKernel8.DefaultCDOL1 ) );


		ok = processC_gpoPrivacy( tlvDB.GetValue( TagKernel8.CardKeyData ) );
		if( !ok )
		{
			// S22 - F, 22.51
			errorIndication.L2 = ErrorIndication.L2_DECRYPTION_FAILED;
			S202122232425_E();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void performRRP()
	{
		Binary terminalEntropy = tlvDB.GetValue( TagEmv.UnpredictableNumber );

		cr.Cmd( ApduEmv.ExchangeRelayResistanceData( terminalEntropy ), RApdu.ST_ANY );
		// CardReader даёт миллисекунды. Лучше так, чем измерять снаружи, т.к. при выводе в лог получаем + затраты на логирование.

		// 21.11
		long diffTimeMicros = cr.cmdTime * 1000;

		// 21.12
		if( cr.rapdu.status != 0x9000 )
			statusError( cr.rapdu.status );

		// 21.14
		if( (cr.resp.size() < 12) || (cr.resp.getU16( 0 ) != 0x800A) )
			parsingError();

		lastERRDResponse = cr.resp.slice( 2, 10 );

		// 21.17
		//Binary deviceRREntropy = lastERRDResponse.first( 4 );
		int minTimeForProcessingRRApdu = lastERRDResponse.slice( 4, 2 ).asU16();
		int maxTimeForProcessingRRApdu = lastERRDResponse.slice( 6, 2 ).asU16();
		int deviceEstimatedTransmissionTimeForRRRapdu = lastERRDResponse.slice( 8, 2 ).asU16();

		int tCmd = (int)Math.min( diffTimeMicros / 100, 0xFFFF );
		int tCApdu = tlvDB.GetValue( TagKernel8.TerminalExpectedTimeForRRCAPDU ).asU16();
		int terminalExpectedRRapdu = tlvDB.GetValue( TagKernel8.TerminalExpectedTimeForRRRAPDU ).asU16();
		int tRapdu = Math.min( deviceEstimatedTransmissionTimeForRRRapdu, terminalExpectedRRapdu );
		int measuredRRProcessingTime = Math.max( 0, tCmd - tCApdu - tRapdu );

		int RRTimeExcess = Math.max( 0, measuredRRProcessingTime - maxTimeForProcessingRRApdu );
		tlvDB.store( TagKernel8.RR_TimeExcess, Bin().addU16( RRTimeExcess ) );

		int minRRGracePeriod = tlvDB.GetValue( TagKernel8.MinimumRRGracePeriod ).asU16();
		// 21.18
		if( measuredRRProcessingTime < Math.max( 0, minTimeForProcessingRRApdu - minRRGracePeriod ) )
		{
			// 21.19
			errorIndication.L2 = ErrorIndication.L2_CARD_DATA_ERROR;
			S202122232425_E();
		}

		int maxRRGracePeriod = tlvDB.GetValue( TagKernel8.MaximumRRGracePeriod ).asU16();
		boolean again = rrpCounter < 2;
		again &= measuredRRProcessingTime > (maxTimeForProcessingRRApdu + maxRRGracePeriod);
		// 21.20
		if( again )
		{
			// 21.21
			rrpCounter++;
			// Рекурсия до 3 команд
			performRRP();
		}
		else
		{
			boolean rrpOk = true;
			// 21.22
			if( measuredRRProcessingTime > (maxTimeForProcessingRRApdu + maxRRGracePeriod) )
			{
				// 21.23
				setTVRBit( TVR.RRTimeLimitsExceeded );
				rrpOk = false;
			}

			// 21.24
			boolean exceeded = (deviceEstimatedTransmissionTimeForRRRapdu != 0) && (terminalExpectedRRapdu != 0);

			int RRTransmissionThreshold = tlvDB.GetValue( TagKernel8.RR_TransmissionTimeMismatchThreshold ).asU16();
			boolean f1 = ((deviceEstimatedTransmissionTimeForRRRapdu * 100) / terminalExpectedRRapdu)  <  RRTransmissionThreshold;

			boolean f2 = (((terminalExpectedRRapdu * 100) / deviceEstimatedTransmissionTimeForRRRapdu)  <  RRTransmissionThreshold);

			int RRAccuracyThreshold = tlvDB.GetValue( TagKernel8.RR_AccuracyThreshold ).asU16();
			boolean f3 = Math.max( 0, measuredRRProcessingTime - minTimeForProcessingRRApdu )  >  RRAccuracyThreshold;

			exceeded &= (f1 || f2 || f3);
			if( exceeded )
			{
				// 21.25
				setTVRBit( TVR.RRThresholdExceeded );
				rrpOk = false;
			}

			// 21
			setTVRBit( TVR.RRPPerformed );
			log.writeln( COLOR_KERNEL8, "RRP done (" + (rrpOk? "OK" : "Failed") + ")" );
		}

	}

	// -----------------------------------------------------------------------------------------------------------------
	private Map<Binary, Binary> readRecords( Arr<Binary> recIds )
	{
		Map<Binary, Binary> records = new TreeMap<>();
		for( Binary recId : recIds )
		{
			cr.Cmd( ApduIso.ReadRecord( recId.get( 0 ), recId.get( 1 ) ), RApdu.ST_ANY );

			if( cr.rapdu.status != 0x9000 )
				statusError( cr.rapdu.status );

			records.put( recId, cr.resp );
		}
		return records;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param rec - TLV with tag 0x70 or 0xDA (encrypted).
	 * @return Decrypted record (TLV with tag 0x70).
	 */
	private Binary decryptRecord( final Binary rec )
	{
		BerTLV tlv = new BerTLV( rec );
		if( tlv.tag == TagEmv.ReadRecordResponseMessageTemplate )
			return rec.clone();

		if( tlv.tag != 0xDA )
			parsingError();

		if( CMC.val >= 0xFFFF )
		{
			errorIndication.L2 = ErrorIndication.L2_DECRYPTION_FAILED;
			S202122232425_E();
		}

		Binary plain = EmvCrypt.cryptAesCTR( aesSKc, CMC, tlv.value );
		Binary res = BerTLV.Tlv( TagEmv.ReadRecordResponseMessageTemplate, plain );

		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processAFL()
	{
		// Parse AFL
		Binary afl = tlvDB.GetValue( TagEmv.AFL );
		Arr<Binary> sdaRecIds = new Arr<Binary>();
		Arr<Binary> recIds = null;
		try
		{
			recIds = EmvUtil.parseAFL( afl, sdaRecIds );
		}
		catch (Throwable ex)
		{
			parsingError();
		}

		Map<Binary, Binary> records = readRecords( recIds );

		for( Binary rec : records.values() )
		{
			if( !BerTLV.isTLV( rec ) )
				parsingError();

			rec.assign( decryptRecord( rec ) );

			if( !tlvDB.ParseAndStoreCardResponse( rec ) )
				parsingError();
		}

		signedRecords = EmvUtil.getSdaRecordsKernel8( records, sdaRecIds );

		log.writeln( COLOR_KERNEL8, "Read AFL records" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Начало транзакции с картой - команды SELECT, GPO, READ RECORDs.
	 * Все объекты данных, полученные с карты, доступны в 'this.tlvDB'
	 * @param termParamsForSession - содержит TagEmv.ApplicationIdentifierTerminal, TagEmv.AmountAuthorisedNumeric
	 * и другие параметры, необходимые для терминала во время сессии.
	 * @return данные сигнала OUT, либо null, если всё ОК и можно продолжать работу.
	 */
	public OUT startTransaction( TlvDatabase termParamsForSession )
	{
		OUT out = null;
		try
		{
			kernel8Start( termParamsForSession );

			// Вместо процесса S - выбираем приложение по AID из tlvDB, tag 'Application Identifier' 9F06
			Binary fci = selectApplication();
			initOnSelectApp( fci );

			getProcessingOptions();

			boolean isRRP = tlvDB.GetValue( TagKernel8.KernelConfiguration ).getBit( 0, 4 );
			isRRP &= tlvDB.GetValue( TagEmv.AIP ).getBit( 1, 0 );
			if( isRRP )
			{
				// S2021 - C
				performRRP();
			}
			else
			{
				setTVRBit( TVR.RRPNotPerformed );
				// S2021 - A
			}

			processAFL();

			sessionStarted = true;
		}
		catch( OUT ex )
		{
			out = ex;
		}
		return out;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Plain TLV или null, Если MAC не совпал.
	 */
	public Binary readData( int tag )
	{
		MUST( sessionStarted, "Kernel8 terminal: Wrong usage" );

		cr.Cmd( ApduEmv.ReadData( tag ), RApdu.ST_ANY );
		if( cr.rapdu.status != 0x9000 )
			tlvDB.store( TagKernel8.ReadDataStatus, Bin("00") );

		Binary data = null;

		if( CMC.val < 0xFFFF )
			data = EmvCrypt.decryptReadData( aesSKc, aesSKi, CMC, cr.resp );

		if( (data == null) || !BerTLV.isTLV( data ) || (new BerTLV( data ).tag != tag) || !tlvDB.ParseAndStoreCardResponse( data ) )
			tlvDB.store( TagKernel8.ReadDataStatus, Bin("00") );

		log.writeln( COLOR_KERNEL8, "Read Data" );

		return data;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void errorMissingDataForCerts()
	{
		errorIndication.L2 = ErrorIndication.L2_CARD_DATA_ERROR;
		// S28-C
		S2627C();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return issuerPublicKey or null if error.
	 */
	private ECAlg processIssuerCertificate( int caPKIndex, Binary caPKKey )
	{
		// RPC.4
		if( !tlvDB.IsNotEmpty( TagEmv.IssuerPublicKeyCertificate ) )
			errorMissingDataForCerts();

		try
		{
			Binary cert = tlvDB.GetValue( TagEmv.IssuerPublicKeyCertificate );

			// Проверки по Book-E, 5.2 Issuer ECC Public Key Validation

			// При парсинге сертификата проверяются п. 1, 2, 3, 5, 10
			IssuerEccCertificate issuerCert = new IssuerEccCertificate().fromBin( cert );

			// 4. Check that the Issuer Identifier matches the leftmost 3-10 digits from the Application PAN obtained from the Card.
			String panStr = tlvDB.GetValue( TagEmv.PAN ).Hex( 0 );
			String issuerIdStr = issuerCert.issuerId.Hex( 0 );
			// Сколько значащих цифр в issuerId
			int lenIId = issuerIdStr.indexOf( 'F' );
			if( lenIId == -1 )
				lenIId = issuerIdStr.length();

			panStr = panStr.substring( 0, lenIId );
			issuerIdStr = issuerIdStr.substring( 0, lenIId );
			if( !panStr.equals( issuerIdStr ) )
				return null;

			// 6. Check that the Certificate Expiration Date is equal to or later than the current date.
			Binary now = Bin( ZonedDateTime.now( ZoneOffset.UTC ).format( DateTimeFormatter.ofPattern("yyyyMMdd") ) );
			if( issuerCert.expirationDate.compareTo( now ) < 0 )
				return null;

			// 7. Check that the RID matches the RID in the first 5 bytes of AID obtained from the Card (DF Name).
			Binary aid = tlvDB.GetValue( TagEmv.DFName );
			if( !issuerCert.RID.equals( aid.first( 5 ) ) )
				return null;

			// 8. Check that the Certification Authority Public Key Index obtained from the Card is the same as the one in Table 5.1.
			if( caPKIndex != issuerCert.caPKIndex )
				return null;

			// 9. Check that the concatenation of the RID, Certification Authority Public Key Index,
			// and Issuer Certificate Serial Number is not present on the Certification Revocation List described in Annex B.2.

			// No CRL in this Kernel8

			ECAlg ecAlg = ecDk.clone();
			ecAlg.setPublic( caPKKey );
			if( !issuerCert.verifySignature( ecAlg ) )
				return null;

			EmvCrypt.restorePublicKey( ecAlg, issuerCert.issuerPublicKeyX );

			return ecAlg;
		}
		catch( Throwable ex )
		{
			return null;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return iccPublicKey or null if error.
	 */
	private ECAlg processICCCertificate( ECAlg issuerKey )
	{
		if( !tlvDB.IsNotEmpty( TagEmv.ICC_PublicKeyCertificate ) )
			errorMissingDataForCerts();
		try
		{
			Binary cert = tlvDB.GetValue( TagEmv.ICC_PublicKeyCertificate );
			// Проверки по Book-E, 5.4  ICC ECC Public Key Validation

			// При парсинге сертификата проверяются п. 1, 2, 3, 5, 6, 7, 8

			IccEccCertificate iccCert = new IccEccCertificate().fromBin( cert );

			// 4. Check that the ICC Certificate Expiration Date and ICC Certificate Expiration Time
			// is equal to or later than the current date and time.
			Binary now = Bin( ZonedDateTime.now( ZoneOffset.UTC ).format( DateTimeFormatter.ofPattern("yyyyMMddHHmm") ) );
			Binary dateTime = Bin( iccCert.expirationDate, iccCert.expirationTime );
			if( dateTime.compareTo( now ) < 0 )
				return null;

			// 9. Check that the SDA Hash already computed by the Kernel is the same as the ICCD Hash recovered from the ICC certificate.
			Binary aip = tlvDB.GetValue( TagEmv.AIP );
			Binary sdaHash = EmvCrypt.calcSDAHash( new SHA256(), signedRecords, extendedSDARelData, aip );
			if( !sdaHash.equals( iccCert.iccdHash ) )
				return null;

			// 10. Check that the ICC Public Key Certificate Signature is valid using the Issuer Public Key as described in section 8.8.7.
			if( !iccCert.verifySignature( issuerKey ) )
				return null;

			ECAlg iccKey = issuerKey.clone();
			iccKey.setPublic( Bin("02").add( iccCert.iccPublicKeyX ) );
			return iccKey;
		}
		catch( Throwable ex )
		{
			return null;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private boolean processCertificates()
	{
		// RPC.2
		if( ! tlvDB.IsNotEmpty( TagEmv.CAPublicKeyIndexICC ) )
			errorMissingDataForCerts();

		// RPC.2a
		int caPKIndex = tlvDB.GetRef( TagEmv.CAPublicKeyIndexICC ).asU16();
		Binary caPKKey = caPublicKeys.get( caPKIndex );
		if( caPKKey == null )
			return false;

		ECAlg issuerKey = processIssuerCertificate( caPKIndex, caPKKey );
		if( issuerKey == null )
			return false;

		// extendedSDARelData уже создан.

		ECAlg iccKey = processICCCertificate( issuerKey );
		if( iccKey == null )
			return false;

		// validate Blinding factor
		if( !EmvCrypt.BDHValidate( iccKey, rRecovered, Pc ) )
			return false;

		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void terminalActionAnalysis()
	{
		long tvr = tlvDB.GetRef( TagEmv.TerminalVerificationResults ).asNum();
		long tacDenial = tlvDB.GetRef( TagKernel8.TerminalActionCodeDenial ).asNum();
		long tacOnline = tlvDB.GetRef( TagKernel8.TerminalActionCodeOnline ).asNum();

		// TAA.1
		if( (tvr & tacDenial) != 0 )
		{
			kernelDecision = KERNEL_DECISION_DECLINE;
			return;
		}

		boolean cardOnlineOnly = !tlvDB.GetRef( TagEmv.AIP ).getBit( 1, 3 );

		int termType = tlvDB.GetRef( TagEmv.TerminalType ).asU16();
		boolean terminalOnlineOnly = (termType == 0x11) || (termType == 0x21) || (termType == 0x14) || (termType == 0x24) || (termType == 0x34);
		boolean terminalOfflineOnly = (termType == 0x23) || (termType == 0x26) || (termType == 0x36) || (termType == 0x13) || (termType == 0x16);

		// TAA.2
		if( terminalOnlineOnly )
		{
			kernelDecision = KERNEL_DECISION_ONLINE;
			return;
		}

		// TAA.3
		if( terminalOfflineOnly )
		{
			// TAA.5
			kernelDecision = cardOnlineOnly ? KERNEL_DECISION_DECLINE : KERNEL_DECISION_ACCEPT;
			return;
		}

		// TAA.4
		if( cardOnlineOnly )
		{
			kernelDecision = KERNEL_DECISION_ONLINE;
			return;
		}

		// TAA.6
		kernelDecision = ((tvr & tacOnline) != 0) ? KERNEL_DECISION_ONLINE : KERNEL_DECISION_ACCEPT;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private boolean isDoLocalAuth()
	{
		return tlvDB.GetRef( TagKernel8.KernelQualifier ).getBit( 1, 7 ) && tlvDB.GetRef( TagEmv.AIP ).getBit( 0, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void prepareForGenAC()
	{
		// 2021222324.14
		if( !( tlvDB.IsNotEmpty( TagEmv.AmountAuthorisedNumeric ) && tlvDB.IsNotEmpty( TagEmv.TransactionDate ) ) )
		{
			// 2021222324.15
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_END_APPLICATION );
			errorIndication.L3 = ErrorIndication.L3_TRANSACTION_DATA_MISSING;
			errorIndication.msgOnError = MessageIdentifier.NA;
			throw createOUT( null );
		}

		Binary amountNumeric = tlvDB.GetValue( TagEmv.AmountAuthorisedNumeric );
		Binary cvmRequiredLimit = tlvDB.GetValue( TagKernel8.ReaderCVMRequiredLimit );
		if( !EmvUtil.IsAmountNumeric( amountNumeric ) || !EmvUtil.IsAmountNumeric( cvmRequiredLimit ) )
		{
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_END_APPLICATION );
			errorIndication.L2 = ErrorIndication.L2_TERMINAL_DATA_ERROR;
			throw createOUT( null );
		}


		Binary cvmCapability;
		// 202122232425.7
		if( amountNumeric.compareTo( cvmRequiredLimit ) == 1 )
		{
			// 202122232425.8
			outcomeParameterSet.setB5Bit( OutcomeParameterSet.BIT_RECEIPT );
			
			// 202122232425.9
			cvmCapability = tlvDB.GetValue( TagKernel8.CVMCapabilityCVMRequired );

			// 202122232425.10
			setTRMDBit( TRMD.CVMLimitExceeded );
		}
		else
		{
			// 202122232425.11
			cvmCapability = tlvDB.GetValue( TagKernel8.CVMCapabilityNoCVMRequired );
		}

		tlvDB.GetRef( TagEmv.TerminalCapabilities ).set( 1, cvmCapability.get( 0 ) );


		// 202122232425.12
		Binary trmd = tlvDB.GetRef( TagEmv.TerminalRiskManagementData );
		trmd.set( 0, cvmCapability.get( 0 ) );

		Binary floorLimit = tlvDB.GetValue( TagKernel8.ReaderContactlessFloorLimit );
		// 202122232425.14
		if( amountNumeric.compareTo( floorLimit ) == 1 )
			// 202122232425.15
			setTVRBit( TVR.TransactionExceedsFloorLimit );

		Binary termAID = tlvDB.GetValue( TagEmv.ApplicationIdentifierTerminal );
		int n = termAID.size();
		Binary cardAID = tlvDB.GetValue( TagEmv.DFName );
		// 202122232425.16
		if( !((n <= cardAID.size()) && termAID.equals( cardAID.first( n ) )) )
			// 202122232425.17
			setTVRBit( TVR.AIDMismatch );


		// 202122232425.18
		if( !isDoLocalAuth() )
			// 202122232425.20
			setTVRBit( TVR.LocalAuthenticationWasNotPerformed );

		// else
			// 202122232425.19
			// Не вызываем здесь, т.к. реакция на ошибки происходит позже, после IAD-MAC.
			// По Book C-8 первый вызов стоит здесь для распараллеливания процесса работы с картой и проверки сертификатов.
			// и через флаги в переменной EDA Status анализ сертификатов не делается повторно при повторном вызове 'processCertificates'.
			// При однопоточной работе всё это не нужно.
			// processCertificates();

		// 202122232425.21
		terminalActionAnalysis();
	}

	// -----------------------------------------------------------------------------------------------------------------
	// S28 - C = same
	// S2930 - H = same
	private void S2627C()
	{
		// 2627.13
		uird1.messageId = MessageIdentifier.Error_OtherCard;
		uird1.status = UIRD.STATUS_NOT_READY;
		uird1.holdTime = tlvDB.GetValue( TagKernel8.MessageHoldTime );

		// 2627.14
		outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_END_APPLICATION );
		outcomeParameterSet.setB5Bit( OutcomeParameterSet.BIT_UI_REQUEST_ON_OUTCOME );
		throw createOUT( uird1 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void parseGenACResponse( RApdu rapdu )
	{
		if( rapdu.status != 0x9000 )
		{
			errorIndication.L2 = ErrorIndication.L2_STATUS_BYTES;
			errorIndication.SW12 = cr.rapdu.status;
			S2627C();
		}

		boolean parseOk = tlvDB.ParseAndStoreCardResponse( rapdu.response );
		if( (rapdu.response.size() < 2) || (rapdu.response.get( 0 ) != TagEmv.ResponseMessageTemplateFormat2) || !parseOk )
		{
			errorIndication.L2 = ErrorIndication.L2_PARSING_ERROR;
			S2627C();
		}

		// 26.14
		boolean ok = tlvDB.IsNotEmpty( TagEmv.ATC );
		ok &= tlvDB.IsNotEmpty( TagEmv.CryptogramInformationData );
		ok &= tlvDB.IsNotEmpty( TagEmv.ApplicationCryptogram );
		ok &= tlvDB.IsNotEmpty( TagKernel8.CardholderVerificationDecision );
		ok &= tlvDB.IsNotEmpty( TagKernel8.EDA_MAC );
		ok &= tlvDB.IsNotEmpty( TagEmv.IAD );
		// 2627.1
		ok &= tlvDB.IsNotEmpty( TagEmv.PAN );
		if( !ok )
		{
			// 26.15
			errorIndication.L2 = ErrorIndication.L2_CARD_DATA_MISSING;
			S2627C();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary createExtSDARelData()
	{
		Binary res = Bin();

		if( !tlvDB.IsNotEmpty( TagKernel8.ExtendedSDATagList ) )
			return res;

		// 2627.8
		Binary extTagList = tlvDB.GetValue( TagKernel8.ExtendedSDATagList );
		Arr<Integer> tags = BerTLV.parseTagList( extTagList );
		for( int tag : tags )
		{
			Binary val = tlvDB.GetValue( tag );
			if( val != null )
				res.add( Tlv( tag, val ) );
			else
				res.add( Tlv( tag, Bin() ) );
		}

		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processIADMAC( Binary genACResponse )
	{
		long tvr = tlvDB.GetRef( TagEmv.TerminalVerificationResults ).asNum();
		boolean isRRPPerformed = (tvr & TVR.RRPPerformed) != 0;
		
		// 2627.11, 2627.12

		Binary msg = Bin();
		msg.add( pdolValues );
		msg.add( cdolRelData );
		if( isRRPPerformed )
		{
			msg.add( tlvDB.GetValue( TagEmv.UnpredictableNumber ) );
			msg.add( lastERRDResponse );
		}

		// Skip TLVs - AC and EDA-MAC
		BerTLV tlv77 = new BerTLV( genACResponse );
		ArrayList<BerTLV> tlvs = new BerTLVList( tlv77.value ).recs;
		for( BerTLV tlv : tlvs )
			if( (tlv.tag != TagEmv.ApplicationCryptogram) && (tlv.tag != TagKernel8.EDA_MAC) )
				msg.add( tlv.toBin() );

		// 7.2.11  Process IAD MAC
		Binary aip = tlvDB.GetValue( TagEmv.AIP );
		Binary sdaHash = EmvCrypt.calcSDAHash( new SHA256(), signedRecords, extendedSDARelData, aip );

		msg.add( sdaHash );

		iadMac = EmvCrypt.calcIadMac( aesSKi, msg );

		// S28 -> IAD MAC OK

		// 28.1
		tlvDB.store( TagKernel8.IAD_MAC, iadMac );

		Binary iad = tlvDB.GetRef( TagEmv.IAD );
		int copyIadMac = (aip.get( 1 ) & 0b00000110) >> 1;
		if( copyIadMac == 0b01 )
		{
			// Default offset
			int offset = tlvDB.GetValue( TagKernel8.DefaultIADMACOffset ).asU16();
			if( (offset + 8) > iad.size() )
			{
				errorIndication.L2 = ErrorIndication.L2_CARD_DATA_ERROR;
				S2627C();
			}
			iad.set( offset, iadMac, 0, iadMac.size() );
		}

		if( copyIadMac == 0b10 )
		{
			Binary val = tlvDB.GetValue( TagKernel8.IAD_MACOffset );
			if( !tlvDB.IsNotEmpty( TagKernel8.IAD_MACOffset ) || (val.asU16() + 8) > iad.size() )
			{
				errorIndication.L2 = ErrorIndication.L2_CARD_DATA_ERROR;
				S2627C();
			}
			iad.set( val.asU16(), iadMac, 0, iadMac.size() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processEDAMAC()
	{
		Binary cardAC = tlvDB.GetValue( TagEmv.ApplicationCryptogram );
		Binary cardEdaMac = tlvDB.GetValue( TagKernel8.EDA_MAC );

		Binary myEdaMac = EmvCrypt.calcEdaMac( aesSKi, cardAC, iadMac );

		if( !myEdaMac.equals( cardEdaMac ) )
		{
			errorIndication.L2 = ErrorIndication.L2_EDA_MAC_FAILED;
			S2627C();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void analyseCVD()
	{
		int cvd = tlvDB.GetValue( TagKernel8.CardholderVerificationDecision ).asU16();
		// 29.25
		if( cvd == CVD.CV_FAILED )
		{
			// 29.26
			outcomeParameterSet.setCVM( OutcomeParameterSet.CVM_NA );
			setTVRBit( TVR.CardholderVerificationWasNotSuccessful );
			tlvDB.store( TagEmv.CVMResults, Bin("3F0001") );
			return;
		}

		long trmd = tlvDB.GetValue( TagEmv.TerminalRiskManagementData ).asNum();
		// 29.27
		if( (cvd == CVD.NO_CVM) && ((trmd & TRMD.NoCVMRequiredContactless) != 0) )
		{
			// 29.28
			tlvDB.store( TagEmv.CVMResults, Bin("1F0002") );
			outcomeParameterSet.setCVM( OutcomeParameterSet.CVM_NO_CVM );
			return;
		}

		// 29.29
		if( (cvd == CVD.SIGNATURE) && ((trmd & TRMD.SignatureContactless) != 0) )
		{
			// 29.30
			tlvDB.store( TagEmv.CVMResults, Bin("1E0000") );
			outcomeParameterSet.setCVM( OutcomeParameterSet.CVM_OBTAIN_SIGNATURE );
			return;
		}

		// 29.31
		if( (cvd == CVD.CDCVM) && ((trmd & TRMD.CDCVMContactless) != 0) )
		{
			// 29.32
			tlvDB.store( TagEmv.CVMResults, Bin("010002") );
			outcomeParameterSet.setCVM( OutcomeParameterSet.CVM_CONFIRMATION_CODE_VERIFIED );
			return;
		}

		// 29.33
		if( (cvd == CVD.NA) )
		{
			// 29.34
			tlvDB.store( TagEmv.CVMResults, Bin("3F0000") );
			outcomeParameterSet.setCVM( OutcomeParameterSet.CVM_NA );
			return;
		}

		// 29.40
		if( (cvd == CVD.ONLINE_PIN) && ((trmd & TRMD.EncipheredPINVerifiedOnlineContactless) != 0) )
		{
			// 29.42
			tlvDB.store( TagEmv.CVMResults, Bin("020000") );
			setTVRBit( TVR.OnlineCVMCaptured );
			outcomeParameterSet.setCVM( OutcomeParameterSet.CVM_ONLINE_PIN );
			return;
		}

		// 29.41
		tlvDB.store( TagEmv.CVMResults, Bin("3F0001") );
		setTVRBit( TVR.CardholderVerificationWasNotSuccessful );
		outcomeParameterSet.setCVM( OutcomeParameterSet.CVM_NA );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void secondChecks( int refControlParam )
	{
		// 29.20 is CID valid?
		int acType = tlvDB.GetRef( TagEmv.CryptogramInformationData ).asU16() & ACType.MASK;
		boolean cidValid = (acType== ACType.TC) && (refControlParam == ACType.TC);
		cidValid |= (acType == ACType.ARQC) && ( (refControlParam == ACType.TC) || (refControlParam == ACType.ARQC) );
		cidValid |= (acType == ACType.AAC);
		if( !cidValid )
		{
			errorIndication.L2 = ErrorIndication.L2_CARD_DATA_ERROR;
			S2627C();
		}

		// 29.21
		if( tlvDB.IsNotEmpty( TagKernel8.CardTVR ) )
		{
			// 29.23
			Binary tvr = tlvDB.GetValue( TagEmv.TerminalVerificationResults );
			Binary mask = tlvDB.GetValue( TagKernel8.KernelReservedTVRMask );
			Binary cardTvr = tlvDB.GetValue( TagKernel8.CardTVR );
			tvr.and( mask );
			mask.xor( Bin(5, 0xFF) );
			cardTvr.and( mask );
			tvr.or( cardTvr );
			tlvDB.store( TagEmv.TerminalVerificationResults, tvr );
		}

		// S29-E
		analyseCVD();

		terminalActionAnalysis();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private boolean writeData( final Binary plainTlv, boolean moreCommands )
	{
		Binary encryptedTlv = EmvCrypt.cryptWriteData( aesSKc, KMC, plainTlv );
		cr.Cmd( ApduEmv.WriteData( encryptedTlv, moreCommands ), RApdu.ST_ANY );
		if( cr.rapdu.status != 0x9000 )
			return false;

		Binary myMac = EmvCrypt.calcDataEnvelopeMac( aesSKi, CMC, plainTlv );
		if( !myMac.equals( cr.resp ) )
			return false;

		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void writeData()
	{
		Binary b = tlvDB.GetRef( TagKernel8.DataEnvelopesToWrite );
		BerTLVList tlvList = new BerTLVList( b );

		boolean res = true;

		for( int i = 0; i < tlvList.recs.size(); ++i )
		{
			boolean isMore = (i != (tlvList.recs.size() - 1));
			res &= writeData( tlvList.recs.get( i ).toBin(), isMore );
		}

		if( res )
			tlvDB.store( TagKernel8.WriteDataStatus, Bin("80") );

		log.writeln( COLOR_KERNEL8, "Write Data done (" + (res ? "OK" : "Not OK") + ")" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private boolean isCardMsgIdAllowed( int cardMsgId )
	{
		Binary allowedMsgIds = tlvDB.GetValue( TagKernel8.MessageIdentifiersOnRestart );

		for( int i = 0; i < allowedMsgIds.size(); ++i )
			if( allowedMsgIds.get( i ) == cardMsgId )
				return true;
		
		return false;
	}

	// -----------------------------------------------------------------------------------------------------------------
	// S2930
	private void finishTransaction()
	{
		// 2930.1a
		// 'Report local authentication failed in TVR' in Kernel Configuration is set?
		boolean isReport = tlvDB.GetValue( TagKernel8.KernelConfiguration ).getBit( 0, 3 );
		if( !isReport )
		{
			// 2930.1b
			long tvr = tlvDB.GetRef( TagEmv.TerminalVerificationResults ).asNum();
			tvr &= ~TVR.LocalAuthenticationFailed;
			tlvDB.store( TagEmv.TerminalVerificationResults, Num_Bin( tvr, 5 ) );
		}

		outcomeParameterSet.setB5Bit( OutcomeParameterSet.BIT_DATA_RECORD );
		errorIndication.msgOnError = MessageIdentifier.NA;

		// 2930.2
		// IsNotEmpty(TagOf(Restart Indicator)) AND ('Restart Requested' in Restart Indicator = RESTART B) ?
		Binary restartIndicator = tlvDB.GetValue( TagKernel8.RestartIndicator );
		if( tlvDB.IsNotEmpty( TagKernel8.RestartIndicator ) && ((restartIndicator.get( 0 ) & 0xF0) == 0x20) )
		{
			uird1.holdTime = tlvDB.GetValue( TagKernel8.MessageHoldTime );
			uird1.status = UIRD.STATUS_NOT_READY;
			uird2.holdTime = Bin("000000");
			uird2.status = UIRD.STATUS_READY_TO_READ;

			uird1.messageId = MessageIdentifier.TryAgain;
			uird2.messageId = MessageIdentifier.TryAgain;

			int cardMsgId = restartIndicator.get( 1 );
			if( (cardMsgId != 0) && isCardMsgIdAllowed( cardMsgId ) )
			{
				uird1.messageId = cardMsgId;
				uird2.messageId = cardMsgId;
			}

			// 2930.9
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_END_APPLICATION );
			outcomeParameterSet.setStart( OutcomeParameterSet.START_B );
			outcomeParameterSet.setB5Bit( OutcomeParameterSet.BIT_UI_REQUEST_ON_RESTART );
			outcomeParameterSet.setB5Bit( OutcomeParameterSet.BIT_UI_REQUEST_ON_OUTCOME );
			throw createOUT( true, uird1, uird2 );
		}

		// S2930-C

		// 2930.10
		uird1.status = UIRD.STATUS_NOT_READY;
		// 2930.11
		outcomeParameterSet.setB5Bit( OutcomeParameterSet.BIT_UI_REQUEST_ON_OUTCOME );

		int acType = tlvDB.GetRef( TagEmv.CryptogramInformationData ).asU16() & ACType.MASK;

		// 2930.12
		if( (acType == ACType.TC) && (kernelDecision == KERNEL_DECISION_ACCEPT) )
		{
			// -------------------
			// S2930-D APPROVED
			// -------------------
			// 2930.13
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_APPROVED );
			// 2930.14
			uird1.holdTime = tlvDB.GetValue( TagKernel8.MessageHoldTime );

			// 2930.15
			if( outcomeParameterSet.getCVM() == OutcomeParameterSet.CVM_OBTAIN_SIGNATURE )
				uird1.messageId = MessageIdentifier.Approved_Sign;
			else
				uird1.messageId = MessageIdentifier.Approved;

			// S2930-G
			throw createOUT( true, uird1, null );
		}

		// S2930-E
		// 2930.18
		if( ((acType == ACType.ARQC) && (kernelDecision != KERNEL_DECISION_DECLINE))
			|| ((kernelDecision == KERNEL_DECISION_ONLINE) && (acType != ACType.AAC)) )
		{
			// -------------------
			// ONLINE
			// -------------------
			// 2930.19
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_ONLINE_REQUEST );
			uird1.holdTime = Bin("000000");
			uird1.messageId = MessageIdentifier.Authorising_PleaseWait;
			throw createOUT( true, uird1, null );
		}

		// -------------------
		// S2930-F DECLINE
		// -------------------

		// 2930.21
		// Check if Transaction Type indicates a cash transaction (cash withdrawal or cash disbursement)
		// or a purchase transaction (purchase or purchase with cashback)
		int trcType = tlvDB.GetValue( TagEmv.TransactionType ).get( 0 );
		boolean isCashOrPurchase = (trcType == 0x01) || (trcType == 0x17) || (trcType == 0x00) || (trcType == 0x19);
		if( !isCashOrPurchase )
		{
			// 2930.25
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_END_APPLICATION );
			// 2930.26
			uird1.holdTime = Bin("000000");
			uird1.messageId = MessageIdentifier.ClearDisplay;
			throw createOUT( true, uird1, null );
		}

		// 2930.22
		if( ! tlvDB.IsNotEmpty( TagKernel8.RestartIndicator ) )
		{
			// 2930.23
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_DECLINED );
			// 2930.24
			uird1.holdTime = tlvDB.GetValue( TagKernel8.MessageHoldTime );
			uird1.messageId = MessageIdentifier.Declined;
			throw createOUT( true, uird1, null );
		}

		// S2930-I
		// 2930.27
		// 'Restart Requested' in Restart Indicator = TRY ANOTHER INTERFACE 
		if( (restartIndicator.get( 0 ) & 0xF0) == 0x30 )
		{
			// 2930.28
			outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_TRY_ANOTHER_INTERFACE );

			int altIntf = restartIndicator.get( 0 ) & 0x0F;
			// 2930.29
			if( (altIntf == 0b0001) || (altIntf == 0b0010) || (altIntf == 0b1111) )
			{
				// 2930.30
				outcomeParameterSet.setAlternateInterface( altIntf << 4 );
			}

			// 2930.35
			uird1.holdTime = tlvDB.GetValue( TagKernel8.MessageHoldTime );
			uird1.messageId = MessageIdentifier.TryAnotherInterface;

			// 2930.31, 2930.32, 2930.33, 2930.34
			int cardMsgId = restartIndicator.get( 1 );
			if( (cardMsgId != 0) && isCardMsgIdAllowed( cardMsgId ) )
				uird1.messageId = cardMsgId;

			throw createOUT( true, uird1, null );
		}

		// S2930-J

		// 2930.36
		outcomeParameterSet.setStatus( OutcomeParameterSet.STATUS_DECLINED );

		// 2930.41
		uird1.holdTime = tlvDB.GetValue( TagKernel8.MessageHoldTime );
		uird1.messageId = MessageIdentifier.Declined;

		// 2930.37, 2930.38, 2930.39, 2930.34
		int cardMsgId = restartIndicator.get( 1 );
		if( (cardMsgId != 0) && isCardMsgIdAllowed( cardMsgId ) )
			uird1.messageId = cardMsgId;

		throw createOUT( true, uird1, null );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверка сертификатов, формирование криптограмм карты, проверка EDA-MAC, Write Data.
	 * @return данные сигнала OUT.
	 */
	public OUT generateAC()
	{
		MUST( sessionStarted, "Kernel8 terminal: Wrong usage" );

		OUT out = null;
		try
		{
			prepareForGenAC();

			int refControlParam = kernelDecision;
			cdolRelData = tlvDB.formDOLValues( tlvDB.GetValue( TagEmv.CDOL1 ) );

			boolean isWriteData = tlvDB.IsNotEmpty( TagKernel8.DataEnvelopesToWrite );
			cr.Cmd( ApduEmv.GenerateAC( refControlParam, cdolRelData, isWriteData ), RApdu.ST_ANY );

			log.writeln( COLOR_KERNEL8, "Generate AC" );

			parseGenACResponse( cr.rapdu );

			extendedSDARelData = createExtSDARelData();

			processIADMAC( cr.resp );
			log.writeln( COLOR_KERNEL8, "IAD-MAC calculated" );

			if( isDoLocalAuth() )
			{
				boolean ok = processCertificates();
				if( !ok )
					setTVRBit( TVR.LocalAuthenticationFailed );
				log.writeln( COLOR_KERNEL8, "Local authentication done (" + (ok ? "OK" : "Failed") + ")" );
			}

			processEDAMAC();
			log.writeln( COLOR_KERNEL8, "EDA-MAC verified" );

			secondChecks( refControlParam );

			if( isWriteData )
				writeData();

			finishTransaction();
		}
		catch( OUT ex )
		{
			out = ex;
		}

		sessionStarted = false;

		return out;
	}

}
