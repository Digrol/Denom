// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8;

import java.util.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.format.*;
import org.denom.smartcard.*;
import org.denom.smartcard.emv.*;
import org.denom.smartcard.emv.kernel8.struct.*;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

/**
 * Терминал с единственным ядром - Kernel8 и выбором только одного приложения по AID.
 * Алгоритмы соответствуют Book C-8, отдельные процессы не выделялись, вместо сигналов - прямые вызовы методов
 * для упрощения реализации.
 * По сути здесь то, что делают процессы K, S, P.
 */
public class TerminalKernel8
{
	private final CardReader cr;
	private final ILog log;
	private Random algRandom;

	public Map<Integer, Binary> caPublicKeys = new LinkedHashMap<>();

	private TagDictKernel8 dict = new TagDictKernel8();

	/**
	 * Конфигурация терминала и ядра
	 */
	private TlvDatabase config;

	// -----------------------------------------------------------------------------------------------------------------
	private final static int STATE_INIT        = 0x01;
	private final static int STATE_GPO_DONE    = 0x02;
	private final static int STATE_GEN_AC_DONE = 0x04;
	private int sessionState;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * TLV-объекты на время одной сессии.
	 */
	public TlvDatabase tlvDB;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * [8 байт] - поле value для TLV Outcome Parameter Set (tag 9F8210).
	 */
	private OutcomeParameterSet outcomeParameterSet = new OutcomeParameterSet();

	private UIRD uird1 = new UIRD();

	private UIRD uird2 = new UIRD();

	private ErrorIndication errorIndication = new ErrorIndication();


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

		// Book C-8, A.1.80
		// b1:   Version 02,
		// b2:   Local authentication enabled,
		// b3:   SC ASI = 00 (P-256, AES),
		// b4:   C ASI  = 10 (P-256, SHA-256),
		// b5-6: FF FF (Not used)
		// b7-8: 00 00 (RFU)
		config.store( TagKernel8.KernelQualifier, Bin("02 80 00 10 FF FF 00 00") );
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

		checkParamPresent( TagKernel8.KernelQualifier );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Outcome Parameter Set,  Discretionary Data.
	 */
	private OUT createOUT()
	{
		tlvDB.store( TagKernel8.ErrorIndication, errorIndication.toBin() );
		return new OUT( tlvDB, outcomeParameterSet, false, null, null );
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
		uird1.holdTime = tlvDB.GetValue( TagKernel8.MessageHoldTime ).clone();

		uird2 = new UIRD();

		errorIndication = new ErrorIndication();
		errorIndication.msgOnError = MessageIdentifier.Error_OtherCard;

		// KS.3, KS.4. Если необходимые теги не заданы в конфигурации и параметрах сессии, то исключение, а не OUT.
		checkMandatoryParams();

		sessionState = STATE_INIT;

		log.writeln( "Kernel started" );
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
	// 1.10
	private void setLanguagePreference()
	{
		if( tlvDB.IsNotEmpty( TagEmv.LanguagePreference ) )
		{
			Binary langPref = tlvDB.GetValue( TagEmv.LanguagePreference );
			langPref.resize( 8 );
			uird1.languagePref = langPref;
			uird2.languagePref = langPref.clone();
		}
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
				return createOUT();
			}

			// 1.10
			setLanguagePreference();

			// 1.11
			// IF ['Support for field off detection' in Card Qualifier is set]
			if( (tlvDB.GetValue( TagKernel8.CardQualifier ).get( 4 ) & 0x80) != 0 )
				outcomeParameterSet.setFieldOffRequest( tlvDB.GetValue( TagKernel8.HoldTimeValue ).get( 0 ) );

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
		MUST( sessionState == STATE_GPO_DONE, "POS terminal: Wrong command flow" );

		cr.Cmd( ApduEmv.ReadData( tag ) );
		return null;
		//return EmvCrypt.decryptReadData( sess.aesSKc, sess.aesSKi, sess.CMC, cr.resp );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Формирование криптограммы карты.
	 * @param referenceControlParameter тип запрашиваемой криптограммы.
	 * @return данные сигнала OUT.
	 */
	public OUT generateAC( int referenceControlParameter, boolean moreCommands )
	{
		MUST( sessionState == STATE_GPO_DONE, "POS terminal: Wrong command flow" );

		OUT out = null;
		try
		{

		}
		catch( OUT ex )
		{
			out = ex;
		}

		sessionState = STATE_GEN_AC_DONE;

		return out;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void writeData( final Binary plainTlv, boolean moreCommands )
	{
		MUST( sessionState == STATE_GEN_AC_DONE, "POS terminal: Wrong command flow" );
		Binary encryptedTlv = null;// = EmvCrypt.cryptWriteData( sess.aesSKc, sess.KMC, plainTlv );
		cr.Cmd( ApduEmv.WriteData( encryptedTlv, moreCommands ) );

//		Binary myMac = EmvCrypt.calcDataEnvelopeMac( sess.aesSKi, sess.CMC, plainTlv );
//		MUST( myMac.equals( cr.resp ), "Wrong card MAC" );
	}

}
