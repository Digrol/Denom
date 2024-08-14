// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.x509;

import java.util.HashMap;
import java.util.Map;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import org.denom.Binary;
import org.denom.format.BerTLV;
import org.denom.format.BerTLVList;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * https://www.rfc-editor.org/rfc/rfc5280
 * SGP.22 v2.5, 4.5.2.1.0.2, Certificates description. eUICC
 * Parse Binary with EUICC certificate into fields
 */
public class CertificateX509v3
{
	protected Binary tbsCertificateFull;
	public BerTLVList tbsCertificate; // value of 'tbsCertificate'

	// value of 'signatureAlgorithm' without SEQUENCE tag:
	// AlgorithmIdentifier.algorithm  |  AlgorithmIdentifier.parameters (OPTIONAL)
	public Binary signatureAlgorithm;

	public Binary signatureValue; // 0x30..  0x02..  0x02

	// -------------------------
	// parsed 'tbsCertificate':
	// -------------------------

	public Binary serialNumber;

	// 'signature' equals to 'signatureAlgorithm'
	
	// type (AttributeType) OID value    ->    value (AttributeValue)
	public HashMap<Binary, BerTLV> issuer = new HashMap<>();

	// seconds since Epoch
	public long validityNotBefore;
	public long validityNotAfter;

	// type (AttributeType) OID value    ->    value (AttributeValue)
	public HashMap<Binary, BerTLV> subject = new HashMap<>();

	// SubjectPublicKeyInfo  ::=  SEQUENCE  {
	//     algorithm            AlgorithmIdentifier,
	//     subjectPublicKey     BIT STRING  }

	// value of 'signatureAlgorithm' without SEQUENCE tag:
	// AlgorithmIdentifier.algorithm  |  AlgorithmIdentifier.parameters (OPTIONAL)
	public Binary subjectPublicKeyAlgorithm;
	public Binary subjectPublicKey;

	Binary issuerUniqueID = Bin();
	Binary subjectUniqueID = Bin();

	public HashMap<Binary, BerTLVList> extensions = new HashMap<>();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return second since Epoch
	 */
	private static long parseTime( BerTLV tlvTime )
	{
		// UTCTime (0x17) or GeneralizedTime (0x18)
		MUST( (tlvTime.tag == 0x17) || (tlvTime.tag == 0x18),"Wrong X.509 Certificate: validity tags: wrong time tag" );
		String s = tlvTime.value.asUTF8();

		MUST( s.charAt( s.length() - 1 ) == 'Z', "Wrong X.509 Certificate: validity time string" );

		String format = (tlvTime.tag == 0x17) ? "yyMMddHHmmssX" : "yyyyMMddHHmmssX";
		OffsetDateTime dateTime = OffsetDateTime.parse( s,  DateTimeFormatter.ofPattern( format ) );
		return dateTime.toEpochSecond();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void parseName( BerTLV tlvName, String fieldName, HashMap<Binary, BerTLV> attributes )
	{
		attributes.clear();
		
		String errMsg = "Wrong X.509 Certificate: " + fieldName;
		MUST( tlvName.tag == 0x30, errMsg );
		BerTLVList tlvs = new BerTLVList( tlvName.value );

		for( BerTLV tlv : tlvs.recs )
		{
			MUST( tlv.tag == 0x31,errMsg );
			BerTLV attribTlv = new BerTLV( tlv.value );
			MUST( attribTlv.tag == 0x30, errMsg );
			BerTLVList tl = new BerTLVList( attribTlv.value );
			MUST( tl.recs.size() == 2, errMsg );
			MUST( tl.recs.get( 0 ).tag == 0x06, errMsg );
			Binary attrOID = tl.recs.get( 0 ).value;
			attributes.put( attrOID, tl.recs.get( 1 ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void parseTbs()
	{
		MUST( tbsCertificate.recs.size() >= 7, "Wrong X.509 Certificate: 'tbsCertificate' tags number < 7" );

		// -----------------------------------------
		// version
		// -----------------------------------------
		BerTLV tlv0 = tbsCertificate.recs.get( 0 );
		MUST( (tlv0.tag == 0xA0) && (tlv0.value.equals( "02  01  02" )), "Wrong X.509 Certificate: version" );

		// -----------------------------------------
		// serialNumber
		// -----------------------------------------
		BerTLV tlv1 = tbsCertificate.recs.get( 1 );
		MUST( tlv1.tag == 0x02, "Wrong X.509 Certificate: serialNumber" );
		serialNumber = tlv1.value;


		// -----------------------------------------
		// signature
		// -----------------------------------------
		BerTLV tlv2 = tbsCertificate.recs.get( 2 );
		MUST( tlv2.tag == 0x30, "Wrong X.509 Certificate: signature" );
		Binary signature = tlv2.value;
		MUST( signature.equals( signatureAlgorithm ), "Wrong X.509 Certificate: 'signature' not equal to 'signatureAlgorithm'" );

		// -----------------------------------------
		// issuer
		// -----------------------------------------
		parseName( tbsCertificate.recs.get( 3 ), "issuer", issuer );

		// -----------------------------------------
		// validity
		// -----------------------------------------
		BerTLV tlv4 = tbsCertificate.recs.get( 4 );
		MUST( tlv4.tag == 0x30, "Wrong X.509 Certificate: validity" );
		BerTLVList tlvs = new BerTLVList( tlv4.value );
		MUST( tlvs.recs.size() == 2, "Wrong X.509 Certificate: validity tags: wrong number" );

		validityNotBefore = parseTime( tlvs.recs.get( 0 ) );
		validityNotAfter = parseTime( tlvs.recs.get( 1 ) );

		// -----------------------------------------
		// subject
		// -----------------------------------------
		parseName( tbsCertificate.recs.get( 5 ), "subject", subject );
		
		// -----------------------------------------
		// subjectPublicKeyInfo
		// -----------------------------------------
		BerTLV tlv6 = tbsCertificate.recs.get( 6 );
		MUST( tlv6.tag == 0x30, "Wrong X.509 Certificate: subjectPublicKeyInfo" );
		tlvs.assign( tlv6.value );
		MUST( (tlvs.recs.size() == 2)
			&& (tlvs.recs.get( 0 ).tag == 0x30) && (tlvs.recs.get( 1 ).tag == 0x03), "Wrong X.509 Certificate: subjectPublicKeyInfo" );

		subjectPublicKeyAlgorithm = tlvs.recs.get( 0 ).value;
		Binary b = tlvs.recs.get( 1 ).value;
		subjectPublicKey = b.last( b.size() - 1 );

		// -----------------------------------------
		// issuerUniqueID (OPTIONAL)
		// -----------------------------------------
		Binary val = tbsCertificate.find( "81" ).value;
		if( !val.empty() )
			issuerUniqueID = val.last( val.size() - 1 );

		// -----------------------------------------
		// subjectUniqueID (OPTIONAL)
		// -----------------------------------------
		val = tbsCertificate.find( "82" ).value;
		if( !val.empty() )
			subjectUniqueID = val.last( val.size() - 1 );

		// -----------------------------------------
		// extensions (OPTIONAL)
		// -----------------------------------------
		extensions.clear();
		val = tbsCertificate.find( "A3/30" ).value;
		if( !val.empty() )
		{
			tlvs.assign( val );
			for( BerTLV tlv : tlvs.recs )
			{
				MUST( tlv.tag == 0x30, "Wrong X.509 Certificate: extensions" );
				BerTLVList extensionTlvs = new BerTLVList( tlv.value );
				BerTLV oidTlv = extensionTlvs.recs.get( 0 );
				MUST( oidTlv.tag == 0x06, "Wrong X.509 Certificate: extensions: oid tag" );
				extensions.put( oidTlv.value, extensionTlvs );
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public CertificateX509v3 fromBin( Binary cert )
	{
		// Certificate  ::=  SEQUENCE  {
		//    tbsCertificate       TBSCertificate,
		//    signatureAlgorithm   AlgorithmIdentifier,
		//    signatureValue       BIT STRING  }
		BerTLVList tlvs = new BerTLVList( cert );

		// Check tag - SEQUENCE
		MUST( (tlvs.recs.size() == 1) && (tlvs.recs.get( 0 ).tag == 0x30 ), "Wrong X.509 Certificate: TLV structure" );
		// The Certificate is a SEQUENCE of three required fields.
		Binary certValue = tlvs.recs.get( 0 ).value;
		tlvs.assign( certValue );
		MUST( tlvs.recs.size() == 3, "Wrong X.509 Certificate: TLV structure" );

		// 1. tbsCertificate
		BerTLV tlv = tlvs.recs.get( 0 );
		MUST( tlv.tag == 0x30, "Wrong X.509 Certificate: 'tbsCertificate' tag != 0x30" );
		tbsCertificateFull = tlvs.recs.get( 0 ).toBin();
		tbsCertificate = new BerTLVList( tlv.value );

		// 2. signatureAlgorithm
		// AlgorithmIdentifier  ::=  SEQUENCE  {
		//     algorithm               OBJECT IDENTIFIER,
		//     parameters              ANY DEFINED BY algorithm OPTIONAL  }
		tlv = tlvs.recs.get( 1 );
		MUST( tlv.tag == 0x30, "Wrong X.509 Certificate: 'signatureAlgorithm' tag != 0x30" );
		signatureAlgorithm = tlv.value;

		// 3. signatureValue
		tlv = tlvs.recs.get( 2 );
		MUST( (tlv.tag == 0x03), "Wrong X.509 Certificate: 'signatureValue' tag != 0x03" );
		signatureValue = tlv.value.last( tlv.value.size() - 1 ); // omit first byte == 0x00

		parseTbs();

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void printTime( StringBuilder sb, long epochSeconds )
	{
		sb.append( Instant.ofEpochSecond( epochSeconds ).atZone( ZoneId.of( "UTC" ) )
				.format( DateTimeFormatter.ofPattern( "yyyy-MM-dd HH:mm:ss z" ) ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String toString()
	{
		StringBuilder sb = new StringBuilder(512);
		sb.append( "serialNumber              : " );
		sb.append( serialNumber.Hex() );
		sb.append( '\n' );

		sb.append( "validityNotBefore         : " );
		printTime( sb, validityNotBefore );
		sb.append( '\n' );

		sb.append( "validityNotAfter          : " );
		printTime( sb, validityNotAfter );
		sb.append( '\n' );

		sb.append( "subjectPublicKeyAlgorithm : " );
		sb.append( subjectPublicKeyAlgorithm.Hex() );
		sb.append( '\n' );

		sb.append( "subjectPublicKey          : " );
		sb.append( subjectPublicKey.Hex() );
		sb.append( '\n' );

		sb.append( "Issuer Name:\n" );
		for( Map.Entry<Binary, BerTLV> entry : issuer.entrySet() )
		{
			sb.append( "    OID : " );
			sb.append( entry.getKey().Hex() );
			sb.append( '\n' );
			String s = "";
			try
			{
				s = entry.getValue().value.asUTF8();
			}
			catch( Throwable ex ){}

			sb.append( "        as Binary : " );
			sb.append( entry.getValue().toBin().Hex() );
			sb.append( '\n' );
			if( !s.isEmpty() )
			{
				sb.append( "        as UTF-8  : " );
				sb.append( s );
				sb.append( '\n' );
			}
		}

		sb.append( "Subject Name:\n" );
		for( Map.Entry<Binary, BerTLV> entry : subject.entrySet() )
		{
			sb.append( "    OID : " );
			sb.append( entry.getKey().Hex() );
			sb.append( '\n' );
			String s = "";
			try
			{
				s = entry.getValue().value.asUTF8();
			}
			catch( Throwable ex ){}

			sb.append( "        as Binary : " );
			sb.append( entry.getValue().toBin().Hex() );
			sb.append( '\n' );
			if( !s.isEmpty() )
			{
				sb.append( "        as UTF-8  : " );
				sb.append( s );
				sb.append( '\n' );
			}
		}

		sb.append( "Extensions:\n" );
		for( Map.Entry<Binary, BerTLVList> entry : extensions.entrySet() )
		{
			sb.append( "    OID : " );
			sb.append( entry.getKey().Hex() );
			sb.append( '\n' );
			sb.append( "    TLV list :\n" );
			sb.append( entry.getValue().toString( 8 ) + "\n" );
		}

		return sb.toString();
	}
}
