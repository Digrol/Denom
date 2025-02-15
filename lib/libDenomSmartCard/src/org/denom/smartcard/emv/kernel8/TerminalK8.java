// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8;

import java.util.LinkedHashMap;
import java.util.Map;

import org.denom.*;
import org.denom.log.*;
import org.denom.crypt.ec.ECAlg;
import org.denom.smartcard.*;
import org.denom.smartcard.emv.*;

import static org.denom.Binary.*;
import static org.denom.Ex.MUST;

/**
 * Work with card application by commands from 'EMV Сontactless Book C-8, Kernel 8 Specification v1.1'.
 * It is not Kernel 8 flow.
 * For tests and research.
 */
public class TerminalK8
{
	/**
	 * Card reader to send commands to.
	 */
	public CardReader cr = null;

	public ILog log = new LogDummy();

	/**
	 * AID of application instance.
	 */
	public Binary appAid = Bin();

	public K8Session session;

	public Map<Integer, Binary> caPublicKeys = new LinkedHashMap<>();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Параметры терминала
	 */
	public Binary kernelQualifier = Bin( "00 00 00 00 00 00 00 00" );

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalK8() {}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalK8( CardReader cr, final Binary aid, ECAlg ecAlg )
	{
		this.cr = cr;
		this.appAid = aid.clone();
		this.session = new K8Session( ecAlg );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalK8 setReader( CardReader reader )
	{
		this.cr = reader;
		session.clear();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalK8 setAID( final Binary aid )
	{
		this.appAid = aid.clone();
		session.clear();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalK8 setECAlg( ECAlg ecAlg )
	{
		this.session = new K8Session( ecAlg );
		session.clear();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalK8 setLog( ILog log )
	{
		this.log = log;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void addCAPublicKey( int caPKIndex, final Binary caPublicKey )
	{
		caPublicKeys.put( caPKIndex, caPublicKey );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getVal( int tag )
	{
		return session.tlvDB.GetValue( tag );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * SELECT card application.
	 * @return card response - FCI.
	 */
	public Binary select()
	{
		cr.Cmd( ApduIso.SelectAID( appAid ), RApdu.ST_ANY );
		MUST( cr.rapdu.isOk() || (cr.rapdu.sw1() == 0x62) || (cr.rapdu.sw1() == 0x63),
			"Can't select card application, status: " + Num_Bin( cr.rapdu.status, 2 ).Hex() );

		session.processFCI( cr.resp );

		return cr.resp.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void getProcessingOptions()
	{
		Binary pdolValues = session.initGPO( kernelQualifier );
		Cmd( ApduEmv.GetProcessingOptions( pdolValues ) );
		session.processGPOResponse( cr.resp );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void readAFLRecords()
	{
		Binary afl = session.tlvDB.GetValue( TagEmv.AFL );

		Arr<Binary> sdaRecIds = new Arr<Binary>();
		Map<Binary, Binary> records = EmvUtil.readAflRecords( cr, EmvUtil.parseAFL( afl, sdaRecIds ) );
		session.processRecords( records, sdaRecIds );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void processCertificates()
	{
		session.processCertificates( caPublicKeys );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param cryptType = A.1.108  Reference Control Parameter
	 * @return
	 */
	public Binary generateAC( int cryptType, boolean moreCommands )
	{
		Binary genACData = session.calcGenerateACRequest();
		Cmd( ApduEmv.GenerateAC( cryptType, genACData, moreCommands ) );
		session.processGenACResponse( cr.resp );
		return cr.resp.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void verifyEdaMac( final Binary sdaHash )
	{
		MUST( session.verifyEdaMac( sdaHash ), "Wrong card EDA-MAC" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary readRecord( int sfi, int recordId )
	{
		Cmd( ApduIso.ReadRecord( sfi, recordId ) );
		Binary plainRecord = session.decryptRecord( cr.resp );
		return plainRecord;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary readRecord( Binary sfi_recId )
	{
		return readRecord( sfi_recId.get(0), sfi_recId.get(1) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверка криптограммы карты
	 * @param MKac
	 */
	public void verifyAC( Binary MKac, boolean includeIADMAC )
	{
		MUST( session.verifyAC( MKac, includeIADMAC ), "Wrong card AC" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void WriteData( final Binary tlv, boolean moreCommands )
	{
		Binary encryptedTlv = session.encryptWriteData( tlv );
		Cmd( ApduEmv.WriteData( encryptedTlv, moreCommands ) );
		MUST( session.verifyWriteDataMac( tlv, cr.resp ), "Wrong card MAC" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Plain TLV или null, Если MAC не совпал.
	 */
	public Binary ReadData( int tag )
	{
		Cmd( ApduEmv.ReadData( tag ) );
		return session.decryptReadData( cr.resp );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private final String thisClassName = TerminalK8.class.getName();

	// -----------------------------------------------------------------------------------------------------------------
	private void Cmd( CApdu capdu )
	{
		cr.callerClassName = thisClassName;
		cr.Cmd( capdu, RApdu.ST_OK );
	}

}
