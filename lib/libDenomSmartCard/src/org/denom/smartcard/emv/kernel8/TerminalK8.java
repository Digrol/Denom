// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8;

import java.util.*;
import org.denom.*;
import org.denom.log.*;
import org.denom.crypt.AES;
import org.denom.crypt.ec.ECAlg;
import org.denom.crypt.ec.Fp.FpCurveAbstract;
import org.denom.crypt.hash.SHA256;
import org.denom.format.*;
import org.denom.smartcard.*;
import org.denom.smartcard.emv.*;
import org.denom.smartcard.emv.certificate.*;
import org.denom.smartcard.emv.kernel8.struct.*;

import static org.denom.Ex.MUST;
import static org.denom.Binary.*;
import static org.denom.format.BerTLV.Tlv;

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

	public Map<Integer, Binary> caPublicKeys = new LinkedHashMap<>();

	public ECAlg ecAlg;
	public int ECNField;

	public int iadOffsetForIadMac = 24;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Параметры терминала
	 */
	public Binary kernelQualifier = Bin( "02 80 00 10 FF FF 00 00" );

	// -----------------------------------------------------------------------------------------------------------------
	public Session sess;
	public class Session
	{
		public TlvDatabase tlvDB;

		// Kernel Message Counter
		public Int KMC = new Int(0);

		// Card Message Counter
		public Int CMC = new Int(0);

		// Terminal ephimeral key pair.
		public ECAlg ecDk;

		// Card public key
		public ECAlg ecQc;

		public Binary inputForIADMAC;
		public Binary inputForAC;
		public Binary IadMac;

		// Blinded card public key
		public Binary Pc;

		public AES aesSKc;
		public AES aesSKi;

		public Binary rRecovered;

		public Binary sdaRecords = Bin();

		public Binary lastERRDResponse;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalK8() {}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalK8( CardReader cr, final Binary aid, ECAlg ecAlg )
	{
		this.cr = cr;
		this.appAid = aid.clone();
		setECAlg( ecAlg );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void resetSession()
	{
		this.sess = new Session();

		sess.tlvDB = new TlvDatabase( new TagDictKernel8() );

		sess.KMC.val = 0x0000;
		sess.CMC.val = 0x8000;
		sess.ecDk = ecAlg.clone();
		sess.ecQc = ecAlg.clone();

		sess.Pc = Bin();
		sess.aesSKc = new AES();
		sess.aesSKi = new AES();
		sess.rRecovered = Bin();
		sess.sdaRecords = Bin();

		sess.lastERRDResponse = null;
		
		sess.inputForIADMAC = Bin();
		sess.inputForAC = Bin();
		sess.IadMac = Bin();

		sess.tlvDB.store( TagEmv.UnpredictableNumber, Bin().random( 4 ) );

	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalK8 setReader( CardReader reader )
	{
		this.cr = reader;
		resetSession();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalK8 setAID( final Binary aid )
	{
		this.appAid = aid.clone();
		resetSession();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalK8 setECAlg( ECAlg ecAlg )
	{
		this.ecAlg = ecAlg.clone();
		ECNField = ((FpCurveAbstract)ecAlg.getCurve()).getNField();
		resetSession();
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
		return sess.tlvDB.GetValue( tag );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processFCI( Binary fci )
	{
		MUST( BerTLV.isTLV( fci ), "Not TLV in response on SELECT" );
		BerTLV tlv = new BerTLV( fci );
		MUST( tlv.tag == TagEmv.FCI, "Not FCI on Select" );

		// Save whole FCI
		sess.tlvDB.store( tlv );
		// And primitive tags in it
		MUST( sess.tlvDB.ParseAndStoreCardResponse( fci ), "Wrong FCI" );
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

		resetSession();

		processFCI( cr.resp );
		return cr.resp.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void getProcessingOptions()
	{
		Binary fci = sess.tlvDB.GetTLV( TagEmv.FCI );

		resetSession();

		if( !fci.empty() )
			processFCI( fci );

		// Generate Terminal EC Key pair.
		sess.ecDk.generateKeyPair();

		Binary Qk = sess.ecDk.getPublic( false );
		Qk = Qk.last( Qk.size()-1 );
		sess.tlvDB.store( TagKernel8.KernelKeyData, Qk );

		sess.tlvDB.store( TagKernel8.KernelQualifier, kernelQualifier );

		// Search PDOL in tlvDB and form PDOL Values (without tag 0x83)
		Binary pdolValues = Bin();
		if( sess.tlvDB.IsNotEmpty( TagEmv.PDOL ) )
			pdolValues = sess.tlvDB.formDOLValues( sess.tlvDB.GetValue( TagEmv.PDOL ) );

		sess.inputForIADMAC.add( pdolValues );

		Cmd( ApduEmv.GetProcessingOptions( pdolValues ) );

		Binary gpoResp = cr.resp;

		// Generate session keys and recover R.
		BerTLV tlvResp = new BerTLV( gpoResp );
		MUST( tlvResp.tag == TagEmv.ResponseMessageTemplateFormat2, "Wrong TLV in GPO response" );

		MUST( sess.tlvDB.ParseAndStoreCardResponse( gpoResp ), "Wrong GPO Response" );

		Binary cardKeyData = sess.tlvDB.GetValue( TagKernel8.CardKeyData );
		MUST( cardKeyData.size() == ECNField * 2, "Wrong GPO Response" );

		sess.Pc = cardKeyData.first( ECNField );

		Binary SKcSKi = EmvCrypt.BDHCalcSessionKeys( sess.ecDk, sess.Pc );
		Binary SKc = SKcSKi.first( 16 );
		Binary SKi = SKcSKi.last( 16 );
		sess.aesSKc.setKey( SKc );
		sess.aesSKi.setKey( SKi );

		Binary encryptedR = cardKeyData.last( ECNField );
		sess.rRecovered = EmvCrypt.BDHRecoverR( sess.aesSKc, encryptedR, sess.CMC );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary exchangeRRData()
	{
		Cmd( ApduEmv.ExchangeRelayResistanceData( sess.tlvDB.GetValue( TagEmv.UnpredictableNumber ) ) );

		BerTLV tlv = new BerTLV( cr.resp );
		MUST( (tlv.tag == 0x80) && (tlv.value.size() == 10), "Wrong response on ExchangeRelayResistanceData" );

		sess.lastERRDResponse = tlv.value;

		return tlv.value;
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

		MUST( tlv.tag == 0xDA, "Wrong tag in record" );
		Binary plain = EmvCrypt.cryptAesCTR( sess.aesSKc, sess.CMC, tlv.value );
		Binary res = BerTLV.Tlv( TagEmv.ReadRecordResponseMessageTemplate, plain );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processRecords( Map<Binary, Binary> records, Arr<Binary> sdaRecIds )
	{
		for( Binary rec : records.values() )
		{
			rec.assign( decryptRecord( rec ) );
			sess.tlvDB.ParseAndStoreCardResponse( rec );
		}

		sess.sdaRecords = EmvUtil.getSdaRecordsKernel8( records, sdaRecIds );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void readAFLRecords()
	{
		Binary afl = sess.tlvDB.GetValue( TagEmv.AFL );

		Arr<Binary> sdaRecIds = new Arr<Binary>();
		Map<Binary, Binary> records = EmvUtil.readAflRecords( cr, EmvUtil.parseAFL( afl, sdaRecIds ) );
		processRecords( records, sdaRecIds );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary readRecord( int sfi, int recordId )
	{
		Cmd( ApduIso.ReadRecord( sfi, recordId ) );
		Binary plainRecord = decryptRecord( cr.resp );
		return plainRecord;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary readRecord( Binary sfi_recId )
	{
		return readRecord( sfi_recId.get(0), sfi_recId.get(1) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary createExtSDARelData()
	{
		Binary res = Bin();

		if( !sess.tlvDB.IsNotEmpty( TagKernel8.ExtendedSDATagList ) )
			return res;

		Binary extTagList = sess.tlvDB.GetValue( TagKernel8.ExtendedSDATagList );
		Arr<Integer> tags = BerTLV.parseTagList( extTagList );
		for( int tag : tags )
		{
			Binary val = sess.tlvDB.GetValue( tag );
			if( val != null )
				res.add( Tlv( tag, val ) );
			else
				res.add( Tlv( tag, Bin() ) );
		}

		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void processCertificates()
	{
		Binary b = sess.tlvDB.GetValue( TagEmv.CAPublicKeyIndexICC );
		MUST( b != null, "CA PK Index absent on card" );
		Binary caKey = caPublicKeys.get( b.asU16() );
		MUST( caKey != null, "Unknown CA Key" );

		ECAlg ecAlg = sess.ecDk.clone();
		ecAlg.setPublic( caKey );

		Binary cert = sess.tlvDB.GetValue( TagEmv.IssuerPublicKeyCertificate );
		MUST( cert != null, "Issuer Public Key Cert absent on card" );
		IssuerEccCertificate issuerCert = new IssuerEccCertificate().fromBin( cert );
		MUST( issuerCert.verifySignature( ecAlg ), "Wrong signature in Issuer ECC Certificate" );

		EmvCrypt.restorePublicKey( ecAlg, issuerCert.issuerPublicKeyX );

		cert = sess.tlvDB.GetValue( TagEmv.ICC_PublicKeyCertificate );
		MUST( cert != null, "ICC Public Key Cert absent on card" );
		IccEccCertificate iccCert = new IccEccCertificate().fromBin( cert );
		MUST( iccCert.verifySignature( ecAlg ), "Wrong signature in ICC ECC Certificate" );

		Binary extendedSDARelData = createExtSDARelData();

		Binary aip = sess.tlvDB.GetValue( TagEmv.AIP );
		Binary myHash = EmvCrypt.calcSDAHash( new SHA256(), sess.sdaRecords, extendedSDARelData, aip );

		MUST( iccCert.iccdHash.equals( myHash ), "Wrong ICCD Hash" );

		// Validate r
		sess.ecQc.setPublic( Bin("02").add( iccCert.iccPublicKeyX ) );
		MUST( EmvCrypt.BDHValidate( sess.ecQc, sess.rRecovered, sess.Pc ), "BDH failed: wrong r" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param cryptType = A.1.108  Reference Control Parameter
	 * @return Ответ карты
	 */
	public Binary generateAC( int cryptType, boolean moreCommands )
	{
		Binary cdolRelData = sess.tlvDB.formDOLValues( sess.tlvDB.GetValue( TagEmv.CDOL1 ) );
		sess.inputForAC.add( cdolRelData.first( 29 ) ); // 6 + 6 + 2 + 5 + 2 + 3 + 1 + 4 = 29
		sess.inputForIADMAC.add( cdolRelData );

		Cmd( ApduEmv.GenerateAC( cryptType, cdolRelData, moreCommands ) );
		
		BerTLV tlv77 = new BerTLV( cr.resp );
		MUST( tlv77.tag == TagEmv.ResponseMessageTemplateFormat2, "Wrong Tag in GENERATE AC Response" );
		MUST( sess.tlvDB.ParseAndStoreCardResponse( cr.resp ), "Wrong GENERATE AC Response" );

		if( sess.lastERRDResponse != null )
		{
			sess.inputForIADMAC.add( sess.tlvDB.GetValue( TagEmv.UnpredictableNumber ) );
			sess.inputForIADMAC.add( sess.lastERRDResponse );
		}

		// Skip TLVs - AC and EDA-MAC
		ArrayList<BerTLV> tlvs = new BerTLVList( tlv77.value ).recs;
		for( BerTLV tlv : tlvs )
			if( (tlv.tag != TagEmv.ApplicationCryptogram) && (tlv.tag != TagKernel8.EDA_MAC) )
				sess.inputForIADMAC.add( tlv.toBin() );

		return cr.resp.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Plain TLV или null, Если MAC не совпал.
	 */
	public Binary ReadData( int tag )
	{
		Cmd( ApduEmv.ReadData( tag ) );
		return EmvCrypt.decryptReadData( sess.aesSKc, sess.aesSKi, sess.CMC, cr.resp );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void WriteData( final Binary plainTlv, boolean moreCommands )
	{
		Binary encryptedTlv = EmvCrypt.cryptWriteData( sess.aesSKc, sess.KMC, plainTlv );
		Cmd( ApduEmv.WriteData( encryptedTlv, moreCommands ) );

		Binary myMac = EmvCrypt.calcDataEnvelopeMac( sess.aesSKi, sess.CMC, plainTlv );
		MUST( myMac.equals( cr.resp ), "Wrong card MAC" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void verifyEdaMac()
	{
		Binary cardAC = sess.tlvDB.GetValue( TagEmv.ApplicationCryptogram );
		MUST( cardAC != null, "Perform Generate AC" );

		Binary extendedSDARelData = createExtSDARelData();
		Binary aip = sess.tlvDB.GetValue( TagEmv.AIP );
		Binary iccdHash = EmvCrypt.calcSDAHash( new SHA256(), sess.sdaRecords, extendedSDARelData, aip );

		sess.inputForIADMAC.add( iccdHash );
		sess.IadMac = EmvCrypt.calcIadMac( sess.aesSKi, sess.inputForIADMAC );
		Binary myEdaMac = EmvCrypt.calcEdaMac( sess.aesSKi, cardAC, sess.IadMac );
		Binary cardEdaMac = sess.tlvDB.GetValue( TagKernel8.EDA_MAC );

		MUST( myEdaMac.equals( cardEdaMac ), "Wrong card EDA-MAC" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверка криптограммы карты.
	 * Если в криптограмму включен IAD-MAC, то сначала вызвать verifyEdaMac.
	 * @param MKac
	 */
	public void verifyAC( Binary MKac, boolean includeIADMAC )
	{
		Binary cardAC = sess.tlvDB.GetValue( TagEmv.ApplicationCryptogram );

		Binary aip = sess.tlvDB.GetValue( TagEmv.AIP );
		Binary iad = sess.tlvDB.GetValue( TagEmv.IAD );
		Binary atc = sess.tlvDB.GetValue( TagEmv.ATC );

		sess.inputForAC.add( aip );
		sess.inputForAC.add( atc );

		if( includeIADMAC )
			iad.set( iadOffsetForIadMac, sess.IadMac, 0, sess.IadMac.size() );

		sess.inputForAC.add( iad );

		AES aes = new AES( MKac );
		Binary SKac = EmvCrypt.calcEmvSessionKeyAC( aes, atc );
		aes.setKey( SKac );

		Binary myAC = EmvCrypt.calcAC( aes, sess.inputForAC );
		MUST( myAC.equals( cardAC ), "Wrong card AC" );
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
