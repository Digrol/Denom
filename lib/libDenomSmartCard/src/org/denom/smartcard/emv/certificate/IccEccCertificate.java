// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.certificate;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import org.denom.Binary;
import org.denom.crypt.ec.ECAlg;
import org.denom.crypt.hash.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * Book E, 5.3  ICC ECC Public Key Certificate.
 */
public class IccEccCertificate
{
	/**
	 * 1. ICC Certificate Format.
	 * Always Hex value '14'.
	 */
	public int certFormat = 0x14; // [1 байт]

	/**
	 * 2. ICC Certificate Encoding.
	 * Always Hex value '00'
	 */
	public int certEncoding = 0x00; // [1 байт]

	/**
	 * 3. ICC Public Key Algorithm Suite Indicator.
	 * Identifies the algorithm suite to be used with the certified ICC Public Key
	 * when establishing the secure channel as defined in Table 8.4.
	 * Always Hex value '00'.
	 */
	public int asi = 0x00; // [1 байт]

	/**
	 * 4. ICC Certificate Expiration Date.
	 * YYYYMMDD (UTC) after which this certificate is invalid.
	 */
	public Binary expirationDate; // [4 байта]

	/**
	 * 5. ICC Certificate Expiration Time.
	 * HHMM (UTC) after which this certificate is invalid.
	 */
	public Binary expirationTime; // [2 байта]

	/**
	 * 6. ICC Certificate Serial Number.
	 * Number unique to the Issuer that signs the Card certificate.
	 */
	public Binary serialNumber; // [6 байт]

	/**
	 * 7. ICCD Hash Encoding.
	 * Always Hex value '01' for this version of the specification, identifying TLV encoding
	 * of the input (except for the AIP where just the value is included) is used when computing the ICCD Hash.
	 */
	public int hashEncoding = 0x01; // [1 байт]

	/**
	 * 8. ICCD Hash Algorithm Indicator.
	 * Identifies the hash algorithm used to compute the ICCD Hash.
	 * Hex value '02' identifying that SHA-256 is used.
	 */
	public int hashAlg = 0x02; // [1 байт]

	/**
	 * 9. ICCD Hash.
	 * Hash over the Static Data to be Authenticated using the hash algorithm 
	 * identified by the ICCD Hash Algorithm Indicator.
	 */
	public Binary iccdHash; // [Nhash байт]

	/**
	 * 10. ICC Public Key.
	 * Representation of ICC Public Key (x-coordinate of ICC Public Key point)
	 * on the curve identified by the ICC Public Key Algorithm Suite Indicator.
	 */
	public Binary iccPublicKeyX; // [Nfield байт]

	/**
	 * 11. ICC Public Key Certificate Signature.
	 * A digital signature on items 1 to 10.
	 * Verified using the Issuer Public Key and associated algorithms identified by the Issuer 
	 * Public Key Algorithm Suite Indicator (in the Issuer certificate).
	 */
	public Binary signature; // [Nsig байт]

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Поля задавать присваиванием или fromBin.
	 */
	public IccEccCertificate() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подготовить поля для генерации сертификата. Заполняет все поля, кроме подписи.
	 * Подписать - в методе sign().
	 * @param serial [6 байт]
	 */
	public IccEccCertificate prepareToSign( int validYears, final Binary serial, Binary iccdHash, ECAlg iccPublic )
	{
		MUST( (serial.size() == 6) && (iccdHash.size() == 32), "Wrong params for Issuer Cert" );

		certFormat = 0x14;
		certEncoding = 0x00;
		asi = 0x00;

		String hex = ZonedDateTime.now().plusYears( validYears ).format( DateTimeFormatter.ofPattern("yyyyMMdd") );
		expirationDate = Bin( hex );
		expirationTime = Bin("23 59");

		serialNumber = serial.clone();

		hashEncoding = 0x01;
		hashAlg = 0x02;

		this.iccdHash = iccdHash.clone();

		Binary pub = iccPublic.getPublic( true );
		iccPublicKeyX = pub.last( pub.size() - 1 );

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить сертификат, разложить сериализованные данные по полям.
	 * @return this
	 */
	public IccEccCertificate fromBin(  final Binary cert )
	{
		certFormat = cert.get( 0 );
		certEncoding = cert.get( 1 );
		asi = cert.get( 2 );
		expirationDate = cert.slice( 3, 4 );
		expirationTime = cert.slice( 7, 2 );
		serialNumber = cert.slice( 9, 6 );
		hashEncoding = cert.get( 15 );
		hashAlg = cert.get( 16 );

		MUST( (certFormat == 0x14) && (certEncoding == 0x00) && (asi == 0x00) && (hashEncoding == 0x01) && (hashAlg == 0x02),
				"Unsupported ICC ECC Cert format" );

		int hashSize = getHashAlgSize();
		int offset = 17;
		iccdHash = cert.slice( offset, hashSize );
		offset += hashSize;

		int NField = getPublicKeyXSize();
		iccPublicKeyX = cert.slice( offset, NField );
		offset += NField;

		signature = cert.last( cert.size() - offset );

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private int getPublicKeyXSize()
	{
		MUST( asi == 0x00, "Unsupported ASI in ICC Certificate" );
		return 32;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private int getHashAlgSize()
	{
		MUST( hashAlg == 0x02, "Unsupported Hash Alg in ICC Certificate" );
		return SHA256.HASH_SIZE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private IHash getHashAlg()
	{
		MUST( hashAlg == 0x02, "Unsupported Hash Alg in ICC Certificate" );
		return new SHA256();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конкатенация полей для формирования или проверки подписи.
	 */
	public Binary formDataToSign()
	{
		Binary b = Bin();
		b.add( certFormat );
		b.add( certEncoding );
		b.add( asi );
		b.add( expirationDate );
		b.add( expirationTime );
		b.add( serialNumber );
		b.add( hashEncoding );
		b.add( hashAlg );
		b.add( iccdHash );
		b.add( iccPublicKeyX );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать все поля сертификата
	 */
	public Binary toBin()
	{
		Binary b = formDataToSign();
		b.add( signature );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean verifySignature( ECAlg issuerPublicKey )
	{
		Binary b = formDataToSign();
		return issuerPublicKey.verifyECSDSA_X( b, getHashAlg(), this.signature );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void sign( ECAlg issuerPrivateKey )
	{
		Binary b = formDataToSign();
		this.signature = issuerPrivateKey.signECSDSA_X( b, getHashAlg() );
	}
}
