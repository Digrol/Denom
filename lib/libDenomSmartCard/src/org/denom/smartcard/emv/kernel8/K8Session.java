// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8;

import java.util.ArrayList;
import java.util.Map;

import org.denom.*;
import org.denom.crypt.AES;
import org.denom.crypt.ec.ECAlg;
import org.denom.format.*;
import org.denom.smartcard.emv.*;
import org.denom.smartcard.emv.certificate.*;
import org.denom.smartcard.emv.kernel8.struct.*;

import static org.denom.Binary.*;
import static org.denom.Ex.MUST;
import static org.denom.smartcard.emv.EmvCrypt.*;

/**
 * Session data on terminal side during work with card application by commands from 'EMV Сontactless Book C-8, Kernel 8 Specification v1.1'.
 */
public class K8Session
{
	public TlvDatabase tlvDB;

	/**
	 * Kernel Message Counter
	 */
	public Int KMC = new Int(0);

	/**
	 * Card Message Counter
	 */
	public Int CMC = new Int(0);

	/**
	 * Terminal ephimeral key pair.
	 */
	public ECAlg ecDk;

	/**
	 * Card public key
	 */
	public ECAlg ecQc;

	public Binary inputForIADMAC;
	public Binary inputForAC;
	public Binary IadMac;

	/**
	 * Blinded card public key
	 */
	public Binary Pc;

	public AES aesSKc;
	public AES aesSKi;

	public Binary rRecovered;

	Binary sdaRecords = Bin();

	// -----------------------------------------------------------------------------------------------------------------
	public K8Session( ECAlg ecAlg )
	{
		this.tlvDB = new TlvDatabase( new TagDictKernel8() );
		this.ecDk = ecAlg.clone();
		clear();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void clear()
	{
		tlvDB.clear();
		KMC.val = 0x0000;
		CMC.val = 0x8000;
		ecDk = ecDk.clone();
		ecQc = ecDk.clone();

		Pc = Bin();
		aesSKc = new AES();
		aesSKi = new AES();
		rRecovered = Bin();
		sdaRecords = Bin();

		inputForIADMAC = Bin();
		inputForAC = Bin();
		IadMac = Bin();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Process card response on SELECT
	 */
	public void processFCI( final Binary fci )
	{
		clear();

		MUST( BerTLV.isTLV( fci ), "Not TLV in response on SELECT" );
		BerTLV tlv = new BerTLV( fci );
		MUST( tlv.tag == TagEmv.FCI, "Not FCI on Select" );

		// Save whole FCI
		tlvDB.store( tlv );
		// And primitive tags in it
		MUST( tlvDB.ParseAndStoreCardResponse( fci ), "Wrong FCI" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Generate Terminal EC Key pair.
	 * Search PDOL in tlvDB and form PDOL Values
	 * @return PDOL Values (without tag 0x83).
	 */
	public Binary initGPO( Binary kernelQualifier )
	{
		Binary fci = tlvDB.GetTLV( TagEmv.FCI );

		clear();

		if( !fci.empty() )
			processFCI( fci );

		ecDk.generateKeyPair();
		Binary Qk = ecDk.getPublic( false );
		Qk = Qk.last( Qk.size()-1 );
		tlvDB.store( TagKernel8.KernelKeyData, Qk );

		tlvDB.store( TagKernel8.KernelQualifier, kernelQualifier );

		Binary pdolValues = Bin();
		if( tlvDB.IsNotEmpty( TagEmv.PDOL ) )
			pdolValues = tlvDB.formDOLValues( tlvDB.GetValue( TagEmv.PDOL ) );

		inputForIADMAC.add( pdolValues );

		return pdolValues;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Generate session keys and recover R.
	 */
	public void processGPOResponse( Binary gpoResponse )
	{
		BerTLV tlvResp = new BerTLV( gpoResponse );
		MUST( tlvResp.tag == TagEmv.ResponseMessageTemplateFormat2, "Wrong TLV in GPO response" );

		MUST( tlvDB.ParseAndStoreCardResponse( gpoResponse ), "Wrong GPO Response" );

		Binary cardKeyData = tlvDB.GetValue( TagKernel8.CardKeyData );
		int ecField = (ecDk.getCurve().getFieldSize() + 7) / 8;
		MUST( cardKeyData.size() == ecField * 2, "Wrong GPO Response" );

		Pc = cardKeyData.first( ecField );

		Binary SKcSKi = BDHCalcSessionKeys( ecDk, Pc );
		Binary SKc = SKcSKi.first( 16 );
		Binary SKi = SKcSKi.last( 16 );
		aesSKc.setKey( SKc );
		aesSKi.setKey( SKi );

		Binary encryptedR = cardKeyData.last( ecField );
		rRecovered = EmvCrypt.BDHRecoverR( aesSKc, encryptedR, CMC );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void validateR( Binary Qc_X )
	{
		ecQc.setPublic( Bin("02").add( Qc_X ) );
		MUST( BDHValidate( ecQc, rRecovered, Pc ), "BDH failed: wrong r" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param rec - TLV with tag 0x70 or 0xDA (encrypted).
	 * @return Decrypted record (TLV with tag 0x70).
	 */
	public Binary decryptRecord( final Binary rec )
	{
		BerTLV tlv = new BerTLV( rec );
		if( tlv.tag == TagEmv.ReadRecordResponseMessageTemplate )
			return rec.clone();

		MUST( tlv.tag == 0xDA, "Wrong tag in record" );
		Binary plain = cryptAesCTR( aesSKc, CMC, tlv.value );
		Binary res = BerTLV.Tlv( TagEmv.ReadRecordResponseMessageTemplate, plain );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void processRecords( Map<Binary, Binary> records, Arr<Binary> sdaRecIds )
	{
		for( Binary rec : records.values() )
		{
			rec.assign( decryptRecord( rec ) );
			tlvDB.ParseAndStoreCardResponse( rec );
		}

		sdaRecords = EmvUtil.getSdaRecords( records, sdaRecIds );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void processCertificates( Map<Integer, Binary> caPublicKeys )
	{
		Binary b = tlvDB.GetValue( TagEmv.CAPublicKeyIndexICC );
		MUST( b != null, "CA PK Index absent on card" );
		Binary caKey = caPublicKeys.get( b.asU16() );
		MUST( caKey != null, "Unknown CA Key" );

		ECAlg ecAlg = ecDk.clone();
		ecAlg.setPublic( caKey );

		Binary cert = tlvDB.GetValue( TagEmv.IssuerPublicKeyCertificate );
		MUST( b != null, "Issuer Public Key Cert absent on card" );
		IssuerEccCertificate issuerCert = new IssuerEccCertificate().fromBin( cert );
		MUST( issuerCert.verifySignature( ecAlg ), "Wrong signature in Issuer ECC Certificate" );

		EmvCrypt.restorePublicKey( ecAlg, issuerCert.issuerPublicKeyX );

		cert = tlvDB.GetValue( TagEmv.ICC_PublicKeyCertificate );
		MUST( cert != null, "ICC Public Key Cert absent on card" );
		IccEccCertificate iccCert = new IccEccCertificate().fromBin( cert );
		MUST( iccCert.verifySignature( ecAlg ), "Wrong signature in ICC ECC Certificate" );
		validateR( iccCert.iccPublicKeyX );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary calcGenerateACRequest()
	{
		Binary cdolRelData = tlvDB.formDOLValues( tlvDB.GetValue( TagEmv.CDOL1 ) );
		inputForAC.add( cdolRelData.first( 29 ) ); // 6 + 6 + 2 + 5 + 2 + 3 + 1 + 4 = 29
		inputForIADMAC.add( cdolRelData );
		return cdolRelData;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void processGenACResponse( final Binary resp )
	{
		BerTLV tlv77 = new BerTLV( resp );
		MUST( tlv77.tag == TagEmv.ResponseMessageTemplateFormat2, "Wrong Tag in GENERATE AC Response" );
		MUST( tlvDB.ParseAndStoreCardResponse( resp ), "Wrong GENERATE AC Response" );

		// Skip TLVs - AC and EDA-MAC
		ArrayList<BerTLV> tlvs = new BerTLVList( tlv77.value ).recs;
		for( BerTLV tlv : tlvs )
			if( (tlv.tag != TagEmv.ApplicationCryptogram) && (tlv.tag != TagKernel8.EDA_MAC) )
				inputForIADMAC.add( tlv.toBin() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean verifyEdaMac( final Binary sdaHash )
	{
		Binary cardAC = tlvDB.GetValue( TagEmv.ApplicationCryptogram );

		inputForIADMAC.add( sdaHash );
		IadMac = EmvCrypt.calcIadMac( aesSKi, inputForIADMAC );
		Binary myEdaMac = EmvCrypt.calcEdaMac( aesSKi, cardAC, IadMac );
		Binary cardEdaMac = tlvDB.GetValue( TagKernel8.EDA_MAC );

		return myEdaMac.equals( cardEdaMac );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Если в криптограмму включен IAD-MAC, то сначала вызвать verifyEdaMac.
	 * @param MKac
	 * @param includeIADMAC
	 */
	public boolean verifyAC( Binary MKac, boolean includeIADMAC )
	{
		Binary cardAC = tlvDB.GetValue( TagEmv.ApplicationCryptogram );

		Binary aip = tlvDB.GetValue( TagEmv.AIP );
		Binary iad = tlvDB.GetValue( TagEmv.IAD );
		Binary atc = tlvDB.GetValue( TagEmv.ATC );

		inputForAC.add( aip );
		inputForAC.add( atc );
		inputForAC.add( iad.slice( 2, 6 ) );
		if( includeIADMAC )
			inputForAC.add( IadMac );

		AES aes = new AES( MKac );
		Binary SKac = EmvCrypt.calcEmvSessionKeyAC( aes, atc );
		aes.setKey( SKac );

		Binary myAC = EmvCrypt.calcAC( aes, inputForAC );

		return myAC.equals( cardAC );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные для WRITE DATA.
	 */
	public Binary encryptWriteData( Binary tlv )
	{
		return EmvCrypt.cryptWriteData( aesSKc, KMC, tlv );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверить MAC от Plain TLV, который карта возвращает в команде WRITE DATA.
	 */
	public boolean verifyWriteDataMac( final Binary plainTlv, final Binary cardMac )
	{
		Binary myMac = calcDataEnvelopeMac( aesSKi, CMC, plainTlv );
		return myMac.equals( cardMac );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать ответ карты на READ DATA.
	 * @return Plain TLV или null, если MAC не совпал.
	 */
	public Binary decryptReadData( final Binary crypt )
	{
		return EmvCrypt.decryptReadData( aesSKc, aesSKi, CMC, crypt );
	}
}
