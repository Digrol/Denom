// Denom.org
// Author:  Alexey Sovkov,  as.sovkov@gmail.com

package org.denom.crypt.ec;

import java.math.BigInteger;

import org.denom.*;
import org.denom.crypt.hash.IHash;
import org.denom.crypt.ec.ECCurve.ECPoint;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

/**
 * Elliptic Curve Qu-Vanstone Implicit Certificate Scheme (Sec 4).
 */
public class ECQV
{
	private ECDSA issuerKey;
	private IHash hashAlg;
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Issuer private key must be set for certificate generation.
	 * Issuer public key must be set for public and private key reconstruction.
	 */
	public ECQV( ECDSA issuerKey, IHash hashAlg )
	{
		this.issuerKey = issuerKey;
		this.hashAlg = hashAlg;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Implicit Сertificate generation (Sec 4, 3.4).
	 * 
	 * @param idInfo - user identification data (arbitrary string).
	 * @param userPublicKey - initial public key.
	 * @param privateKeyData - [out] private key reconstruction data.
	 * @return reconstruction point.
	 */
	public Binary generateCert( final Binary idInfo, final ECDSA userPublicKey, Binary privateKeyData )
	{
		// reconstruction point
		ECPoint Pu;
		Binary PuBin;
		
		MUST( userPublicKey.getCurve().equals( issuerKey.getCurve() ), "User and issuer curve parameters not match" );
		
		// issuer key pair (k, kG)
		ECCurve ecCurve = issuerKey.getCurve();
		ECDSA kkG = new ECDSA( ecCurve );
		
		BigInteger n = ecCurve.getOrder();
		BigInteger dCa = new BigInteger( 1, issuerKey.getPrivate().getBytes() );
		BigInteger e;

		do
		{
			kkG.generateKeyPair();

			// Pu = Ru + kG
			ECPoint Ru = ecCurve.decodePoint( userPublicKey.getPublic() );
			ECPoint kG = ecCurve.decodePoint( kkG.getPublic() );
			Pu = Ru.add( kG );
			PuBin = Pu.getEncoded( true );
			
			e = calculateE( n, Bin( idInfo, PuBin ) );

		} while( Pu.multiply( e ).add( ecCurve.getG().multiply( dCa ) ).equals( ecCurve.getInfinity() ) );

		// r = ek + dCA (mod n)
		BigInteger k = new BigInteger( 1, kkG.getPrivate().getBytes() );
		BigInteger r = e.multiply( k ).add( dCa ).mod( n );
		
		int mLen = ( ecCurve.getFieldSize() + 7 ) / 8;
		privateKeyData.assign( integerToOctetString( r, mLen ) );
		
		return PuBin;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Public key reconstruction. (Sec 4, 3.5).
	 * 
	 * @param idInfo - user identification data.
	 * @param reconstructionPoint - public key reconstruction data.
	 * @return reconstructed user public key.
	 */
	public ECDSA extractPublic( final Binary idInfo, final Binary reconstructionPoint )
	{
		ECCurve ecCurve = issuerKey.getCurve();
		BigInteger n = ecCurve.getOrder();
		
		// Pu from reconstruction point
		ECPoint Pu = ecCurve.decodePoint( reconstructionPoint );
		
		ECPoint Qca = ecCurve.decodePoint( issuerKey.getPublic() );
		BigInteger e = calculateE( n, Bin( idInfo, reconstructionPoint ) );

		// Qu = ePu + Qca
		Binary Qu = Pu.multiply( e ).add( Qca ).getEncoded( false );
		return new ECDSA( ecCurve ).setPublic( Qu );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Private key reconstruction (Sec 4, 3.6).
	 * 
	 * @param idInfo - user identification data.
	 * @param reconstructionPoint - public key reconstruction data.
	 * @param privateKeyData - private key reconstruction data.
	 * @param userPrivateKey - initial private key.
	 * @return reconstructed user private key.
	 */
	public ECDSA extractPrivate( final Binary idInfo, final Binary reconstructionPoint, final Binary privateKeyData, 
			final ECDSA userPrivateKey )
	{
		ECDSA uPubKey = extractPublic( idInfo, reconstructionPoint );
		
		ECCurve ecCurve = userPrivateKey.getCurve();
		BigInteger n = ecCurve.getOrder();
		BigInteger e = calculateE( n, Bin( idInfo, reconstructionPoint ) );
		
		// Check that the 'r' is less than 'n'
		BigInteger r = new BigInteger( 1, privateKeyData.getBytes() );
		MUST( n.compareTo( r ) == 1, "Octet String value is larger than modulus" );

		// private key kU.
		BigInteger kU = new BigInteger( 1, userPrivateKey.getPrivate().getBytes() );
		
		// dU = r + e*kU (mod n)
		BigInteger dU = r.add( e.multiply( kU ) ).mod( n );
		
		ECDSA uPrivKey = new ECDSA( ecCurve );
		int mLen = ( ecCurve.getFieldSize() + 7 ) / 8;
		uPrivKey.setPrivate( integerToOctetString( dU, mLen ) );
		
		// check key pair
		MUST( uPrivKey.getPublic().equals( uPubKey.getPublic() ) );

		return uPrivKey;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Self-Signed Implicit Сertificate generation (Sec 4, 3.7).

	 * @param idInfo - user identification data (arbitrary string).
	 * @param userPrivateKey - [out] calculated private key.
	 * @return reconstruction point
	 */
	public Binary generateCertSelf( final Binary idInfo, ECDSA userPrivateKey )
	{
		ECCurve ecCurve = issuerKey.getCurve();
		BigInteger n = ecCurve.getOrder();
		
		MUST( userPrivateKey.getCurve().equals( issuerKey.getCurve() ), "User and issuer curve parameters not match" );

		ECPoint Pu = ecCurve.decodePoint( issuerKey.getPublic() );
		Binary PuBin = Pu.getEncoded( true );
		
		BigInteger e = calculateE( n, Bin( idInfo, PuBin ) );

		BigInteger k = new BigInteger( 1, issuerKey.getPrivate().getBytes() );
		BigInteger r = e.multiply( k ).mod( n );

		int mLen = ( ecCurve.getFieldSize() + 7 ) / 8;
		userPrivateKey.setPrivate( integerToOctetString( r, mLen ) );
		
		return PuBin;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Public key reconstruction from Self-Signed Implicit Сertificate (Sec 4, 3.8).
	 * 
	 * @param idInfo - user identification data.
	 * @param reconstructionPoint - public key reconstruction data.
	 * @return reconstructed user public key corresponding idInfo.
	 */
	public ECDSA extractPublicSelf( final Binary idInfo, final Binary reconstructionPoint )
	{
		ECCurve ecCurve = issuerKey.getCurve();
		BigInteger n = ecCurve.getOrder();
		
		ECPoint Pu = ecCurve.decodePoint( reconstructionPoint );
		
		BigInteger e = calculateE( n, Bin( idInfo, reconstructionPoint ) );
		Binary Qu = Pu.multiply( e ).getEncoded( false );
		
		return new ECDSA( ecCurve ).setPublic( Qu );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Hashing to Integers Modulo n (Sec 4, 2.3).
	 */
	private BigInteger calculateE( BigInteger n, Binary s )
	{
		Binary hash = hashAlg.calc( s );
		
		int log2n = n.bitLength() - 1; // floor
		int messageBitLength = hash.size() * 8;

		BigInteger e = new BigInteger( 1, hash.getBytes() );
		if( log2n < messageBitLength )
		{
			e = e.shiftRight( messageBitLength - log2n );
		}
		
		return e;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Integer-to-Octet-String Conversion (Sec 1, 2.3.7).
	 *
	 * @param x - integer to convert.
	 * @param desiredLen - output string len.
	 * @return binary string containing converted x value.
	 */
	private static Binary integerToOctetString( BigInteger x, int desiredLen )
	{
		MUST( x.signum() == 1, "Integer is not positive" );
		MUST( x.compareTo( new BigInteger( "2" ).pow( 8 * desiredLen ) ) == -1, "Integer is larger than expected" );
		
		byte[] xBin = x.toByteArray();
		int srcOffset = ( xBin[0] == 0x00 )? 1 : 0;
		int srcLen = ( xBin[0] == 0x00 )? ( xBin.length - 1 ) : xBin.length;

		if( srcLen < desiredLen )
		{
			return Bin( Bin( desiredLen - srcLen ), new Binary( xBin, srcOffset, srcLen ) );
		}
		else
		{
			return new Binary( xBin, srcOffset, srcLen );
		}
	}

}
