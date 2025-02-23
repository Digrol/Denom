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
	private final static int STATE_SELECTED    = 0x02;
	private final static int STATE_GPO_DONE    = 0x03;
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
	private Binary outcomeParameterSet = Bin( 8 );

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
	private void checkParamPresent( TlvDatabase db, int tag )
	{
		if( !db.IsPresent( tag ) )
			THROW( "Tag " + Binary.Num_Bin( tag, 0 ).Hex() + " (" + dict.find( tag ).name + ") is absent in POS terminal parameters" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверяем наличие обязательных параметров терминала.
	 * Book C-8, A.3  Configuration Data Objects
	 */
	private void checkMandatoryParams( TlvDatabase db )
	{
		checkParamPresent( db, TagEmv.AdditionalTerminalCapabilities );
		checkParamPresent( db, TagEmv.ApplicationIdentifierTerminal );
		checkParamPresent( db, TagEmv.ApplicationVersionNumberTerminal );
		checkParamPresent( db, TagKernel8.CardDataInputCapability );
		checkParamPresent( db, TagKernel8.CVMCapabilityCVMRequired );
		checkParamPresent( db, TagKernel8.CVMCapabilityNoCVMRequired );
		checkParamPresent( db, TagKernel8.DefaultIADMACOffset );
		checkParamPresent( db, TagKernel8.DiscretionaryDataTagList );
		checkParamPresent( db, TagKernel8.HoldTimeValue );
		checkParamPresent( db, TagKernel8.KernelConfiguration );
		checkParamPresent( db, TagKernel8.KernelReservedTVRMask );
		checkParamPresent( db, TagKernel8.MaximumRRGracePeriod );
		checkParamPresent( db, TagKernel8.MessageHoldTime );
		checkParamPresent( db, TagKernel8.MessageIdentifiersOnRestart );
		checkParamPresent( db, TagKernel8.MinimumRRGracePeriod );
		checkParamPresent( db, TagKernel8.ReaderContactlessFloorLimit );
		checkParamPresent( db, TagKernel8.ReaderCVMRequiredLimit );
		checkParamPresent( db, TagKernel8.RR_AccuracyThreshold );
		checkParamPresent( db, TagKernel8.RR_TransmissionTimeMismatchThreshold );
		checkParamPresent( db, TagKernel8.SecurityCapability );
		checkParamPresent( db, TagKernel8.TagMappingList );
		checkParamPresent( db, TagKernel8.TerminalActionCodeDenial );
		checkParamPresent( db, TagKernel8.TerminalActionCodeOnline );
		checkParamPresent( db, TagEmv.TerminalCountryCode );
		checkParamPresent( db, TagKernel8.TerminalExpectedTimeForRRCAPDU );
		checkParamPresent( db, TagKernel8.TerminalExpectedTimeForRRRAPDU );
		checkParamPresent( db, TagEmv.TerminalRiskManagementData );
		checkParamPresent( db, TagEmv.TerminalType );
		checkParamPresent( db, TagKernel8.TimeoutValue );
		checkParamPresent( db, TagEmv.TransactionType );

		checkParamPresent( db, TagKernel8.KernelQualifier );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void resetSessionVars( TlvDatabase termParamsForSession )
	{
		tlvDB = config.clone();
		tlvDB.append( termParamsForSession );

		uird1 = new UIRD();
		uird2 = new UIRD();

		checkMandatoryParams( tlvDB );
		sessionState = STATE_INIT;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processFCI( Binary fci )
	{
		MUST( BerTLV.isTLV( fci ), "Not TLV in response on SELECT" );
		BerTLV tlv = new BerTLV( fci );
		MUST( tlv.tag == TagEmv.FCI, "Not FCI on Select" );

		// Save whole FCI
		tlvDB.store( tlv );
		// And primitive tags in it
		MUST( tlvDB.ParseAndStoreCardResponse( fci ), "Wrong FCI" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void selectApplication()
	{
		Binary appAid = tlvDB.GetValue( TagEmv.ApplicationIdentifierTerminal );
		
		cr.Cmd( ApduIso.SelectAID( appAid ), RApdu.ST_ANY );
		MUST( cr.rapdu.isOk() || (cr.rapdu.sw1() == 0x62) || (cr.rapdu.sw1() == 0x63),
			"Can't select card application, status: " + Num_Bin( cr.rapdu.status, 2 ).Hex() );

		processFCI( cr.resp );

		sessionState = STATE_SELECTED;
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
			resetSessionVars( termParamsForSession );
			selectApplication();
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
