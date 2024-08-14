// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.denom.Binary;
import org.denom.format.*;
import org.denom.crypt.ec.ECCurve.ECPoint;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;
import static org.denom.format.BerTLV.Tlv;

/**
 * EC-DSA as described in X9.62
 */
public class ECDSA
{
	private final ECCurve curve;
	private final BigInteger N;
	private final BigInteger H;
	private final BigInteger HInv;
	private final int nSize;

	private ECPoint Q = null; // Public Key
	private BigInteger D = null; // Private Key

	private final SecureRandom random = new SecureRandom();
	private BigInteger fixedK = null; // for test only

	private static final Binary OID_EC_KEY = ASN1OID.toBin( "1.2.840.10045.2.1" );
	private final Binary oidEcParams;

	// -----------------------------------------------------------------------------------------------------------------
	public ECDSA( ECCurve curve )
	{
		this.curve = curve;
		this.oidEcParams = !curve.getOid().isEmpty() ? ASN1OID.toBin( curve.getOid() ) : Bin();
		this.N = curve.getOrder();
		this.H = curve.getCofactor();
		this.HInv = H.modInverse( N );
		this.nSize = (curve.getFieldSize() + 7) / 8; // bytes
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Creates copy of this object WITHOUT KEYS.
	 */
	public ECDSA clone()
	{
		return new ECDSA( this.curve );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public ECCurve getCurve()
	{
		return this.curve;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Check public key set. Calc it from private if not set.
	 */
	private void checkPublic()
	{
		if( Q != null )
			return;
		MUST( D != null, "Private key for ECDSA not set" );
		this.Q = curve.GMul( D ).normalize();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ECDSA setPublic( final Binary publicKey )
	{
		this.Q = curve.decodePoint( publicKey );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ECDSA setPublicX509( final Binary tlv )
	{
		Binary key = new BerTLVList( tlv ).find( "30/03" ).value;
		key = key.last( key.size() - 1 );
		this.Q = curve.decodePoint( key );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Compressed public point Q
	 */
	public Binary getPublic()
	{
		return getPublic( true );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getPublic( boolean compressed )
	{
		checkPublic();
		return Q.getEncoded( compressed );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return ASN1 TLV
	 */
	public Binary getPublicX509()
	{
		Binary key = getPublic( false );

		// Public Key container
		Binary res = Tlv( 0x30, ""
				+ Tlv( 0x30, "" + Tlv( 0x06, OID_EC_KEY ) + Tlv( 0x06, oidEcParams ) )
				+ Tlv( 0x03, "00" + key ) );

		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ECDSA setPrivate( final Binary privateKey )
	{
		MUST( privateKey.size() == nSize, "Wrong PrivateKey size for ECDSA" );
		D = new BigInteger( 1, privateKey.getBytes() );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ECDSA setPrivatePKCS8( final Binary tlv )
	{
		BerTLVList l = new BerTLVList( tlv );
		l.assign( l.find( "30/04" ).value );
		Binary d = l.find( "30/04" ).value;
		if( d.size() < nSize )
		{
			Binary b = Bin( nSize );
			b.set( nSize - d.size(), d, 0, d.size() );
			d = b;
		}
		setPrivate( d );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getPrivate()
	{
		MUST( D != null, "Private key for ECDSA not set" );
		return ECCurve.BigInt2Bin( nSize, D );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return ASN1 TLV
	 */
	public Binary getPrivatePKCS8()
	{
		MUST( D != null, "Private key for ECDSA not set" );
		Binary key = ECCurve.BigInt2Bin( nSize, D );
		Binary keyInfo = Tlv( 0x30, "02 01 01" + Tlv( 0x04, key ) );
		Binary res = Tlv( 0x30, "02 01 00"
			+ Tlv( 0x30, "" + Tlv( 0x06, OID_EC_KEY ) + Tlv( 0x06, oidEcParams ) )
			+ Tlv( 0x04, keyInfo ) );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ECDSA generateKeyPair()
	{
		int nBitLength = N.bitLength();
		int minWeight = nBitLength >>> 2;

		for( ;; )
		{
			D = new BigInteger( nBitLength, random );

			if( (D.compareTo( BigInteger.valueOf( 2 ) ) > 0)
				&& (D.compareTo( N ) < 0)
				&& (ECCurve.getNafWeight( D ) >= minWeight) )
			{
				break;
			}
		}

		Q = curve.GMul( D ).normalize();

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * For test only purposes
	 */
	public void setFixedK( final Binary k )
	{
		this.fixedK = new BigInteger( 1, k.getBytes() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private BigInteger generateK()
	{
		if( fixedK != null )
		{
			return fixedK;
		}

		int nBitLen = N.bitLength();
		BigInteger k;
		do
		{
			k = new BigInteger( nBitLen, random );
		}
		while( k.equals( BigInteger.ZERO ) || k.compareTo( N ) >= 0 );

		return k;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return r || s.
	 */
	public Binary sign( Binary messageHash )
	{
		MUST( D != null, "Private key for ECDSA not set" );

		BigInteger e = calculateE( N, messageHash.getBytes() );
		BigInteger r;
		BigInteger s;
		do
		{
			BigInteger k = generateK();
			ECPoint p = curve.GMul( k ).normalize();
			r = p.getAffineXCoord().toBigInteger().mod( N );
			s = k.modInverse( N ).multiply( e.add( D.multiply( r ) ) ).mod( N );
		}
		while( r.equals( BigInteger.ZERO ) || s.equals( BigInteger.ZERO ) ); // very very rare case
		

		return Bin( ECCurve.BigInt2Bin( nSize, r ), ECCurve.BigInt2Bin( nSize, s ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return TLV with R and S.
	 */
	public Binary signStd( Binary messageHash )
	{
		MUST( D != null, "Private key for ECDSA not set" );

		BigInteger e = calculateE( N, messageHash.getBytes() );
		BigInteger r;
		BigInteger s;
		do
		{
			BigInteger k = generateK();
			ECPoint p = curve.GMul( k ).normalize();
			r = p.getAffineXCoord().toBigInteger().mod( N );
			s = k.modInverse( N ).multiply( e.add( D.multiply( r ) ) ).mod( N );
		}
		while( r.equals( BigInteger.ZERO ) || s.equals( BigInteger.ZERO ) ); // very very rare case

		return Tlv( 0x30, "" + Tlv( 0x02, Bin( r.toByteArray() ) ) + Tlv( 0x02, Bin( s.toByteArray() ) ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * this.r and this.s must be set.
	 */
	private boolean verifyImpl( Binary hash, BigInteger r, BigInteger s )
	{
		checkPublic();

		BigInteger e = calculateE( N, hash.getBytes() );

		// r in the range [1,n-1]
		if( r.compareTo( BigInteger.ONE ) < 0 || r.compareTo( N ) >= 0 )
		{
			return false;
		}

		// s in the range [1,n-1]
		if( s.compareTo( BigInteger.ONE ) < 0 || s.compareTo( N ) >= 0 )
		{
			return false;
		}

		BigInteger c = s.modInverse( N );

		BigInteger u1 = e.multiply( c ).mod( N );
		BigInteger u2 = r.multiply( c ).mod( N );

		ECPoint point = curve.sumOfTwoMultiplies( curve.getG(), u1, Q, u2 );

		if( point.isInfinity() )
		{
			return false;
		}

		BigInteger v = point.normalize().getAffineXCoord().toBigInteger().mod( N );
		return v.equals( r );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param sign - r || s.
	 */
	public boolean verify( Binary hash, Binary sign )
	{
		BigInteger r = new BigInteger( 1, sign.first( sign.size() / 2 ).getBytes() );
		BigInteger s = new BigInteger( 1, sign.last( sign.size() / 2 ).getBytes() );
		return verifyImpl( hash, r, s );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean verifyStd( Binary hash, Binary sign )
	{
		BerTLV tlv = new BerTLV( sign );
		BigInteger r = new BigInteger( tlv.find( 0x02, 1 ).value.getBytes() );
		BigInteger s = new BigInteger( tlv.find( 0x02, 2 ).value.getBytes() );
		return verifyImpl( hash, r, s );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected BigInteger calculateE( BigInteger n, byte[] message )
	{
		int log2n = n.bitLength();
		int messageBitLength = message.length * 8;

		BigInteger e = new BigInteger( 1, message );
		if( log2n < messageBitLength )
		{
			e = e.shiftRight( messageBitLength - log2n );
		}
		return e;
	}

	// =================================================================================================================
	// Encryption and transformations
	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Process a single EC point using the basic ElGamal algorithm.
	 * @return the result of the Elgamal process.
	 */
	public ECPoint[] encrypt( ECPoint point )
	{
		checkPublic();
		BigInteger k = generateK();
		return new ECPoint[]{
			curve.GMul( k ).normalize(),
			Q.multiply( k ).add( curve.cleanPoint( point ) ).normalize()
		};
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Decrypt EC pair producing the original EC point.
	 */
	public ECPoint decrypt( ECPoint[] pair )
	{
		MUST( D != null, "Private key for EC decrypt not set" );
		ECPoint tmp = curve.cleanPoint( pair[0] ).multiply( D );
		ECPoint res = curve.cleanPoint( pair[1] ).subtract( tmp ).normalize();
		return res;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Transform an existing cipher test pair using the ElGamal algorithm. Note: it is assumed this
	 * transform has been initialised with the same public key that was used to create the original cipher text.
	 * @param cipherText the EC point to process.
	 * @return returns a new ECPair representing the result of the process.
	 */
	public ECPoint[] transformRandom( ECPoint[] cipherText )
	{
		checkPublic();
		BigInteger k = generateK();
		return new ECPoint[] {
				curve.GMul( k ).add( curve.cleanPoint( cipherText[0] ) ).normalize(),
				Q.multiply( k ).add( curve.cleanPoint( cipherText[1] ) ).normalize()
		};
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Transform an existing cipher text pair using the ElGamal algorithm. Note: the input
	 * cipherText will need to be preserved in order to complete the transformation to the new public key.
	 *
	 * @param cipherText the EC point to process.
	 * @return returns a new ECPair representing the result of the process.
	 */
	public ECPoint[] transform( ECPoint[] cipherText )
	{
		checkPublic();

		BigInteger k = generateK();

		return new ECPoint[] {
			curve.GMul( k ).normalize(),
			Q.multiply( k ).add( curve.cleanPoint( cipherText[1] ) ).normalize()
		};
	}

	// =================================================================================================================
	// AGREEMENT
	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * P1363 7.2.1 ECSVDP-DH.
	 * ECSVDP-DH is Elliptic Curve Secret Value Derivation Primitive, Diffie-Hellman version.
	 * Derives a shared secret from one private key and another public key.
	 */
	public Binary calcDH( final Binary otherPublicQ )
	{
		MUST( D != null, "Private key for ECDH not set" );

		ECPoint q = curve.decodePoint( otherPublicQ );
		BigInteger d = this.D;
		if( !this.H.equals( BigInteger.ONE ) )
		{
			d = HInv.multiply( d ).mod( N );
			q = q.multiply( H );
		}

		ECPoint p = q.multiply( d ).normalize();
		MUST( !p.isInfinity(), "Infinity is not a valid agreement value for ECDH" );

		return ECCurve.BigInt2Bin( nSize, p.getAffineXCoord().toBigInteger() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * P1363 7.2.2 ECSVDP-DHC.
	 * ECSVDP-DHC is Elliptic Curve Secret Value Derivation Primitive, Diffie-Hellman version with
	 * cofactor multiplication.
	 * Derives a shared secret from one private key and another public key.
	 */
	public Binary calcDHC( final Binary otherPublicQ )
	{
		MUST( D != null, "Private key for ECDH not set" );

		BigInteger hd = H.multiply( D ).mod( N );
		ECPoint q = curve.decodePoint( otherPublicQ );
		ECPoint p = q.multiply( hd ).normalize();
		MUST( !p.isInfinity(), "Infinity is not a valid agreement value for ECDHC" );

		return ECCurve.BigInt2Bin( nSize, p.getAffineXCoord().toBigInteger() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * EC Unified static/ephemeral agreement as described in NIST SP 800-56A using EC co-factor Diffie-Hellman.
	 * this - staticPrivate.
	 * @return agreement
	 */
	public Binary calcECDHCUnified( final ECDSA ephemeralPrivate, final Binary otherStaticPublic, final Binary otherEphemeralPublic )
	{
		return Bin( ephemeralPrivate.calcDHC( otherEphemeralPublic ), this.calcDHC( otherStaticPublic ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * The ECMQV Primitive as described in SEC-1, 3.4.
	 */
	public Binary calcMQVAgreement( final ECDSA ephemeral, final Binary otherStaticPublic, final Binary otherEphemeralPublic )
	{
		MUST( D != null, "Private key for ECDH not set" );

		int e = (N.bitLength() + 1) / 2;
		BigInteger powE = BigInteger.ONE.shiftLeft( e );

		ECPoint q1v = curve.decodePoint( otherStaticPublic );
		ECPoint q2v = curve.decodePoint( otherEphemeralPublic );

		BigInteger x = ephemeral.Q.getAffineXCoord().toBigInteger();
		BigInteger xBar = x.mod( powE );
		BigInteger Q2UBar = xBar.setBit( e );
		BigInteger s = D.multiply( Q2UBar ).add( ephemeral.D ).mod( N );

		BigInteger xPrime = q2v.getAffineXCoord().toBigInteger();
		BigInteger xPrimeBar = xPrime.mod( powE );
		BigInteger Q2VBar = xPrimeBar.setBit( e );

		BigInteger hs = H.multiply( s ).mod( N );

		ECPoint p = curve.sumOfTwoMultiplies( q1v, Q2VBar.multiply( hs ).mod( N ), q2v, hs ).normalize();
		MUST( !p.isInfinity(), "Infinity is not a valid agreement value for MQV" );

		return ECCurve.BigInt2Bin( nSize, p.getAffineXCoord().toBigInteger() );
	}

}
