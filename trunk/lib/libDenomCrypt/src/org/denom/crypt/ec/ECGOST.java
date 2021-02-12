package org.denom.crypt.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.denom.Binary;
import org.denom.crypt.ec.ECCurve.ECPoint;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * GOST R 34.10 Signature Algorithm
 */
public class ECGOST
{
	private ECCurve curve;
	private BigInteger N;
	private int NSize;

	public ECPoint publicQ = null;
	public BigInteger privateD = null;

	private BigInteger fixedK = null; // for test only
	private SecureRandom random = new SecureRandom();

	// -----------------------------------------------------------------------------------------------------------------
	public ECGOST( ECCurve curve )
	{
		this.curve = curve;
		this.N = curve.getOrder();
		this.NSize = (curve.getFieldSize() + 7) / 8; // bytes
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ECGOST setPublic( final Binary publicQ )
	{
		this.publicQ = curve.decodePoint( publicQ );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Check public key set. Calc it from private if not set.
	 */
	private void checkPublic()
	{
		if( publicQ != null )
			return;
		MUST( privateD != null, "Public key for ECGOST not set" );
		this.publicQ = curve.GMul( privateD ).normalize();
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
		return publicQ.getEncoded( compressed );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ECGOST setPrivate( final Binary privateD )
	{
		this.privateD = new BigInteger( 1, privateD.getBytes() );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getPrivate()
	{
		MUST( privateD != null, "Private key for ECDSA not set" );
		return ECCurve.BigInt2Bin( NSize, privateD );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * generates an EC key pair in accordance with X9.62 section 5.2.1 pages 26, 27.
	 */
	public ECGOST generateKeyPair()
	{
		int nBitLength = N.bitLength();
		int minWeight = nBitLength >>> 2;

		for( ;; )
		{
			privateD = new BigInteger( nBitLength, random );

			if( (privateD.compareTo( BigInteger.valueOf( 2 ) ) >= 0)
				&& (privateD.compareTo( N ) < 0)
				&& (ECCurve.getNafWeight( privateD ) >= minWeight) )
			{
				break;
			}
		}

		publicQ = curve.GMul( privateD );

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
	 * @param hash - GOST3411 hash.
	 * @return r || s.
	 */
	public Binary sign( Binary hash )
	{
		MUST( privateD != null, "Private key for ECGOST not set" );

		BigInteger e = new BigInteger( 1, hash.getBytes() );
		BigInteger r;
		BigInteger s;
		do
		{
			BigInteger k = generateK();
			ECPoint p = curve.GMul( k ).normalize();
			r = p.getAffineXCoord().toBigInteger().mod( N );
			s = (k.multiply( e )).add( privateD.multiply( r ) ).mod( N );
		}
		while( r.equals( BigInteger.ZERO ) || s.equals( BigInteger.ZERO ) ); // very very rare case

		return Bin( ECCurve.BigInt2Bin( NSize, r ), ECCurve.BigInt2Bin( NSize, s ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param sign - r || s.
	 */
	public boolean verify( Binary hash, Binary sign )
	{
		checkPublic();

		BigInteger r = new BigInteger( 1, sign.first( sign.size() / 2 ).getBytes() );
		BigInteger s = new BigInteger( 1, sign.last( sign.size() / 2 ).getBytes() );
		BigInteger e = new BigInteger( 1, hash.getBytes() );

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

		BigInteger v = e.modInverse( N );
		BigInteger z1 = s.multiply( v ).mod( N );
		BigInteger z2 = (N.subtract( r )).multiply( v ).mod( N );
		ECPoint point = curve.sumOfTwoMultiplies( curve.getG(), z1, publicQ, z2 ).normalize();

		// components must be bogus.
		if( point.isInfinity() )
		{
			return false;
		}

		BigInteger R = point.getAffineXCoord().toBigInteger().mod( N );

		return R.equals( r );
	}
}
