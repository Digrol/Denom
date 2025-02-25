// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.certificate;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import org.denom.Binary;
import org.denom.Int;
import org.denom.crypt.ec.ECAlg;
import org.denom.crypt.hash.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * Book E, 5.3  Issuer ECC Public Key Certificate.
 */
public class IssuerEccCertificate
{
	/**
	 * 1. Issuer Certificate Format.
	 * Always Hex value '12'.
	 */
	public int certFormat = 0x12; // [1 байт]

	/**
	 * 2. ICC Certificate Encoding.
	 * Always Hex value '00'
	 */
	public int certEncoding = 0x00; // [1 байт]

	/**
	 * 3. Issuer Identifier.
	 * Leftmost 3-10 digits from the PAN padded to the right with hex 'F's.
	 */
	public Binary issuerId; // [5 байт]

	/**
	 * 4. Issuer Public Key Algorithm Suite Indicator.
	 * Identifies the algorithm suite to be used with the Issuer Public Key when verifying Issuer 
	 * signatures as defined in Table 8.3. Always Hex value '10'.
	 */
	public int asi = 0x10; // [1 байт]

	/**
	 * 5. Issuer Certificate Expiration Date.
	 * YYYYMMDD (UTC) after which this certificate is invalid.
	 */
	public Binary expirationDate; // [4 байта]

	/**
	 * 6. Issuer Certificate Serial Number.
	 * Number unique to the Certification Authority that signs the Issuer certificate.
	 */
	public Binary serialNumber; // [3 байта]

	/**
	 * 7. RID
	 * Identifies the Payment System to which the Issuer Public Key is associated.
	 */
	public Binary RID; // [5 байт]

	/**
	 * 8. Certification Authority Public Key Index.
	 * In conjunction with the RID, identifies which Certification Authority Public Key
	 * and associated algorithms to use when verifying the Issuer certificate.
	 */
	public int caPKIndex; // [1 байт]

	/**
	 * 9. Issuer Public Key.
	 * Representation of Issuer Public Key (x-coordinate of Issuer Public Key point)
	 * on the curve identified by Issuer Public Key Algorithm Suite Indicator.
	 */
	public Binary issuerPublicKeyX; // [Nfield байт]

	/**
	 * 10. Issuer Public Key Certificate Signature.
	 * A digital signature on items 1 to 9.
	 * Verified using the Certification Authority Public Key and associated algorithms 
	 * identified by the Certification Authority Public Key Index.
	 */
	public Binary signature; // [Nsig байт]

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Поля задавать присваиванием или fromBin.
	 */
	public IssuerEccCertificate() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подготовить поля для генерации сертификата. Заполняет все поля, кроме подписи.
	 * Подписать - в методе sign().
	 * @param RID [5 байт].
	 * @param issuerId [5 байт]. IIN с паддингом справа 'F'.
	 * @param serial [3 байта].
	 */
	public IssuerEccCertificate prepareToSign( final Binary RID, int caPKIndex, final Binary issuerId, int validYears,
			final Binary serial, ECAlg issuerPublic )
	{
		MUST( (issuerId.size() == 5) && (serial.size() == 3) && (RID.size() == 5) && Int.isU8( caPKIndex ), "Wrong params for Issuer Cert" );

		certFormat = 0x12;
		certEncoding = 0x00;
		this.issuerId = issuerId.clone();
		asi = 0x10;

		String hex = ZonedDateTime.now( ZoneOffset.UTC ).plusYears( validYears ).format( DateTimeFormatter.ofPattern("yyyyMMdd") );
		expirationDate = Bin( hex );

		serialNumber = serial.clone();

		this.RID = RID.clone();

		this.caPKIndex = caPKIndex;

		Binary pub = issuerPublic.getPublic( true );
		issuerPublicKeyX = pub.last( pub.size() - 1 );

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить сертификат, разложить сериализованные данные по полям.
	 * @return this
	 */
	public IssuerEccCertificate fromBin( final Binary cert )
	{
		certFormat = cert.get( 0 );
		certEncoding = cert.get( 1 );
		issuerId = cert.slice( 2, 5 );
		asi = cert.get( 7 );
		expirationDate = cert.slice( 8, 4 );
		serialNumber = cert.slice( 12, 3 );
		RID = cert.slice( 15, 5 );
		caPKIndex = cert.get( 20 );

		MUST( (certFormat == 0x12) && (certEncoding == 0x00) && (asi == 0x10), "Unsupported Issuer ECC Cert format" );

		int NField = getPublicKeyXSize();
		int offset = 21;
		issuerPublicKeyX = cert.slice( offset, NField );
		offset += NField;

		signature = cert.last( cert.size() - offset );

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private int getPublicKeyXSize()
	{
		MUST( asi == 0x10, "Unsupported ASI in Issuer Certificate" );
		return 32;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private IHash getHashAlg()
	{
		MUST( asi == 0x10, "Unsupported ASI in Issuer Certificate" );
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
		b.add( issuerId );
		b.add( asi );
		b.add( expirationDate );
		b.add( serialNumber );
		b.add( RID );
		b.add( caPKIndex );
		b.add( issuerPublicKeyX );

		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать все поля сертификата.
	 */
	public Binary toBin()
	{
		Binary b = formDataToSign();
		b.add( signature );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean verifySignature( ECAlg caPublicKey )
	{
		Binary b = formDataToSign();
		return caPublicKey.verifyECSDSA_X( b, getHashAlg(), this.signature );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void sign( ECAlg caPrivateKey )
	{
		Binary b = formDataToSign();
		this.signature = caPrivateKey.signECSDSA_X( b, getHashAlg() );
	}

}
