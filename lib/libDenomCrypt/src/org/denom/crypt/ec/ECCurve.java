package org.denom.crypt.ec;

import java.math.BigInteger;
import org.denom.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.*;

/**
 * Base class for an elliptic curve.
 * All curves extend this class.
 * Actually it is domain params for specific curve.
 */
public abstract class ECCurve
{
	private String oid;

	private ECElement a;
	private ECElement b;
	private BigInteger order;
	private BigInteger cofactor;

	private ECPoint G;
	private ECPoint infinity; // used also for creating Points

	protected ECElement myElement; // for creating new Elements

	// Call init() to initialize object
	protected ECCurve() {}

	// -----------------------------------------------------------------------------------------------------------------
	public static BigInteger Hex2BigInt( String hexStr )
	{
		return new BigInteger( 1, new Binary( hexStr ).getBytes() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static Binary BigInt2Bin( int len, final BigInteger bi )
	{
		byte[] bytes = bi.toByteArray();
		if( bytes.length == len )
		{
			return Bin(bytes);
		}

		int start = 0;
		int count = bytes.length;
		if( bytes[ 0 ] == 0 )
		{
			start = 1;
			count = bytes.length - 1;
		}

		MUST( count <= len, "standard length exceeded for value" );
		Binary res = Bin( len );
		res.set( len - count, bytes, start, count );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void init( ECElement element, ECPoint infinity,
			String oid, String aHex, String bHex, String orderHex, String cofactorHex, String gPointHex )
	{
		this.myElement = element;
		this.infinity = infinity;
		this.oid = oid;

		this.a = fromBigInteger( Hex2BigInt( aHex ) );
		this.b = fromBigInteger( Hex2BigInt( bHex ) );
		this.order = Hex2BigInt( orderHex );
		this.cofactor = Hex2BigInt( cofactorHex );

		this.G = decodePoint( Bin( gPointHex ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ECPoint getInfinity()
	{
		return infinity;
	}

	public final String getOid()
	{
		return oid;
	}

	public final ECPoint getG()
	{
		return G;
	}

	public final ECElement getA()
	{
		return a;
	}

	public final ECElement getB()
	{
		return b;
	}

	public final BigInteger getOrder()
	{
		return order;
	}

	public final BigInteger getCofactor()
	{
		return cofactor;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public final ECElement fromBigInteger( BigInteger x )
	{
		return myElement.create( x );
	}


	protected final ECPoint createRawPoint( ECElement x, ECElement y )
	{
		return infinity.create( x, y );
	}


	protected final ECPoint createRawPoint( ECElement x, ECElement y, ECElement[] zs )
	{
		return infinity.create( x, y, zs );
	}


	public ECPoint createPoint( BigInteger x, BigInteger y )
	{
		return infinity.create( fromBigInteger( x ), fromBigInteger( y ) );
	}


	public abstract int getFieldSize();


	protected abstract ECPoint decompressPoint( int yTilde, BigInteger X1 );


	// -----------------------------------------------------------------------------------------------------------------
	public ECPoint importPoint( ECPoint p )
	{
		if( this == p.getCurve() )
		{
			return p;
		}
		if( p.isInfinity() )
		{
			return getInfinity();
		}
		p = p.normalize();

		return createPoint( p.getXCoord().toBigInteger(), p.getYCoord().toBigInteger() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ECPoint cleanPoint( ECPoint p )
	{
		return decodePoint( p.getEncoded( false ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static BigInteger fromUnsignedByteArray( byte[] buf, int off, int length )
	{
		byte[] mag = buf;
		if( off != 0 || length != buf.length )
		{
			mag = new byte[ length ];
			System.arraycopy( buf, off, mag, 0, length );
		}
		return new BigInteger( 1, mag );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Decode a point on this curve from its ASN.1 encoding. The different encodings are taken
	 * account of, including point compression for <code>F<sub>p</sub></code> (X9.62 s 4.2.1 pg 17).
	 * @return The decoded point.
	 */
	public ECPoint decodePoint( Binary encoded )
	{
		ECPoint p = null;
		int expectedLength = (getFieldSize() + 7) / 8;

		int type = encoded.get( 0 );
		switch( type )
		{
			case 0x00: // infinity
			{
				MUST( encoded.size() == 1, "Incorrect length for infinity encoding" );
				p = getInfinity();
				break;
			}
			case 0x02: // compressed
			case 0x03: // compressed
			{
				MUST( encoded.size() == (expectedLength + 1), "Incorrect length for compressed encoding" );
				int yTilde = type & 1;
				BigInteger X = fromUnsignedByteArray( encoded.getBytes(), 1, expectedLength );
				p = decompressPoint( yTilde, X );
				break;
			}
			case 0x04: // uncompressed
			{
				MUST( encoded.size() == (2 * expectedLength + 1), "Incorrect length for uncompressed encoding" );

				BigInteger X = fromUnsignedByteArray( encoded.getBytes(), 1, expectedLength );
				BigInteger Y = fromUnsignedByteArray( encoded.getBytes(), 1 + expectedLength, expectedLength );
				p = createPoint( X, Y );
				break;
			}
			case 0x06: // hybrid
			case 0x07: // hybrid
			{
				MUST( encoded.size() == (2 * expectedLength + 1), "Incorrect length for uncompressed encoding" );
				BigInteger X = fromUnsignedByteArray( encoded.getBytes(), 1, expectedLength );
				BigInteger Y = fromUnsignedByteArray( encoded.getBytes(), 1 + expectedLength, expectedLength );
				MUST( Y.testBit( 0 ) == (type == 0x07), "Inconsistent Y coordinate in hybrid encoding" );
				p = createPoint( X, Y );
				break;
			}
			default:
				THROW( "Invalid point encoding 0x" + Integer.toString( type, 16 ) );
		}

		MUST( p.isValid(), "Invalid point" );
		MUST( (type == 0x00) || !p.isInfinity(), "Invalid infinity encoding" );

		return p;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Multiply fixed ECPoint 'G' by by 'k', i.e. 'p' is added 'k' times to itself.
	 */
	public ECPoint GMul( final BigInteger k )
	{
		return G.multiplyComb( k );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public ECPoint sumOfTwoMultiplies( ECPoint P, BigInteger a, ECPoint Q, BigInteger b )
	{
		Q = importPoint( Q );
		return implShamirsTrickWNaf( P, a, Q, b );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean equals( ECCurve other )
	{
		return (this == other) || ( (null != other) && getOrder().equals( other.getOrder() )
				&& a.toBigInteger().equals( other.a.toBigInteger() )
				&& b.toBigInteger().equals( other.b.toBigInteger() ) );
	}

	@Override
	public boolean equals( Object obj )
	{
		return this == obj || (obj instanceof ECCurve && equals( (ECCurve)obj ));
	}

	@Override
	public int hashCode()
	{
		return getOrder().hashCode() ^ Integer.rotateLeft( a.toBigInteger().hashCode(), 8 )
				^ Integer.rotateLeft( b.toBigInteger().hashCode(), 16 );
	}


	// =================================================================================================================

	private static final int[] DEFAULT_WINDOW_SIZE_CUTOFFS = new int[] { 13, 41, 121, 337, 897, 2305 };

	// -----------------------------------------------------------------------------------------------------------------
	static int getNafWeight( BigInteger k )
	{
		if( k.signum() == 0 )
		{
			return 0;
		}

		BigInteger _3k = k.shiftLeft( 1 ).add( k );
		BigInteger diff = _3k.xor( k );

		return diff.bitCount();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static int[] generateCompactNaf( BigInteger k )
	{
		MUST( (k.bitLength() >>> 16) == 0, "'k' must have bitlength < 2^16" );

		if( k.signum() == 0 )
		{
			return new int[ 0 ];
		}

		BigInteger _3k = k.shiftLeft( 1 ).add( k );

		int bits = _3k.bitLength();
		int[] naf = new int[ bits >> 1 ];

		BigInteger diff = _3k.xor( k );

		int highBit = bits - 1, length = 0, zeroes = 0;
		for( int i = 1; i < highBit; ++i )
		{
			if( !diff.testBit( i ) )
			{
				++zeroes;
				continue;
			}

			int digit = k.testBit( i ) ? -1 : 1;
			naf[ length++ ] = (digit << 16) | zeroes;
			zeroes = 1;
			++i;
		}

		naf[ length++ ] = (1 << 16) | zeroes;

		if( naf.length > length )
		{
			naf = trim( naf, length );
		}

		return naf;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static int[] generateCompactWindowNaf( int width, BigInteger k )
	{
		if( width == 2 )
		{
			return generateCompactNaf( k );
		}

		MUST( (width >= 2) && (width <= 16), "'width' must be in the range [2, 16]" );
		MUST( Int.isU16( k.bitLength() ), "'k' must have bitlength < 2^16" );

		if( k.signum() == 0 )
		{
			return new int[ 0 ];
		}

		int[] wnaf = new int[ k.bitLength() / width + 1 ];

		// 2^width and a mask and sign bit set accordingly
		int pow2 = 1 << width;
		int mask = pow2 - 1;
		int sign = pow2 >>> 1;

		boolean carry = false;
		int length = 0, pos = 0;

		while( pos <= k.bitLength() )
		{
			if( k.testBit( pos ) == carry )
			{
				++pos;
				continue;
			}

			k = k.shiftRight( pos );

			int digit = k.intValue() & mask;
			if( carry )
			{
				++digit;
			}

			carry = (digit & sign) != 0;
			if( carry )
			{
				digit -= pow2;
			}

			int zeroes = length > 0 ? pos - 1 : pos;
			wnaf[ length++ ] = (digit << 16) | zeroes;
			pos = width;
		}

		// Reduce the WNAF array to its actual length
		if( wnaf.length > length )
		{
			wnaf = trim( wnaf, length );
		}

		return wnaf;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static byte[] generateNaf( BigInteger k )
	{
		if( k.signum() == 0 )
		{
			return new byte[ 0 ];
		}

		BigInteger _3k = k.shiftLeft( 1 ).add( k );

		int digits = _3k.bitLength() - 1;
		byte[] naf = new byte[ digits ];

		BigInteger diff = _3k.xor( k );

		for( int i = 1; i < digits; ++i )
		{
			if( diff.testBit( i ) )
			{
				naf[ i - 1 ] = (byte)(k.testBit( i ) ? -1 : 1);
				++i;
			}
		}

		naf[ digits - 1 ] = 1;

		return naf;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Computes the Window NAF (non-adjacent Form) of an integer.
	 * @param width The width <code>w</code> of the Window NAF. The width is defined as the minimal
	 * number <code>w</code>, such that for any <code>w</code> consecutive digits in the resulting
	 * representation, at most one is non-zero.
	 * @param k The integer of which the Window NAF is computed.
	 * @return The Window NAF of the given width, such that the following holds:
	 * <code>k = &sum;<sub>i=0</sub><sup>l-1</sup> k<sub>i</sub>2<sup>i</sup>
	 * </code>, where the <code>k<sub>i</sub></code> denote the elements of the returned
	 * <code>byte[]</code>.
	 */
	private static byte[] generateWindowNaf( int width, BigInteger k )
	{
		if( width == 2 )
		{
			return generateNaf( k );
		}

		MUST( (width >= 2) && (width <= 8) );

		if( k.signum() == 0 )
		{
			return new byte[ 0 ];
		}

		byte[] wnaf = new byte[ k.bitLength() + 1 ];

		// 2^width and a mask and sign bit set accordingly
		int pow2 = 1 << width;
		int mask = pow2 - 1;
		int sign = pow2 >>> 1;

		boolean carry = false;
		int length = 0, pos = 0;

		while( pos <= k.bitLength() )
		{
			if( k.testBit( pos ) == carry )
			{
				++pos;
				continue;
			}

			k = k.shiftRight( pos );

			int digit = k.intValue() & mask;
			if( carry )
			{
				++digit;
			}

			carry = (digit & sign) != 0;
			if( carry )
			{
				digit -= pow2;
			}

			length += (length > 0) ? pos - 1 : pos;
			wnaf[ length++ ] = (byte)digit;
			pos = width;
		}

		// Reduce the WNAF array to its actual length
		if( wnaf.length > length )
		{
			wnaf = trim( wnaf, length );
		}

		return wnaf;
	}


	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Determine window width to use for a scalar multiplication of the given size.
	 * 
	 * @param bits the bit-length of the scalar to multiply by
	 * @return the window size to use
	 */
	private static int getWindowSize( int bits )
	{
		return getWindowSize( bits, DEFAULT_WINDOW_SIZE_CUTOFFS );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Determine window width to use for a scalar multiplication of the given size.
	 * 
	 * @param bits the bit-length of the scalar to multiply by
	 * @param windowSizeCutoffs a monotonically increasing list of bit sizes at which to increment
	 * the window width
	 * @return the window size to use
	 */
	private static int getWindowSize( int bits, int[] windowSizeCutoffs )
	{
		int w = 0;
		for( ; w < windowSizeCutoffs.length; ++w )
		{
			if( bits < windowSizeCutoffs[ w ] )
			{
				break;
			}
		}
		return w + 2;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	private static byte[] trim( byte[] a, int length )
	{
		byte[] result = new byte[ length ];
		System.arraycopy( a, 0, result, 0, result.length );
		return result;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static int[] trim( int[] a, int length )
	{
		int[] result = new int[ length ];
		System.arraycopy( a, 0, result, 0, result.length );
		return result;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static ECPoint[] resizeTable( ECPoint[] a, int length )
	{
		ECPoint[] result = new ECPoint[ length ];
		System.arraycopy( a, 0, result, 0, a.length );
		return result;
	}

	// -----------------------------------------------------------------------------------------------------------------
	static ECPoint implShamirsTrickWNaf( ECPoint P, BigInteger k, ECPoint Q, BigInteger l )
	{
		boolean negK = k.signum() < 0;
		boolean negL = l.signum() < 0;

		k = k.abs();
		l = l.abs();

		int widthP = Math.max( 2, Math.min( 16, getWindowSize( k.bitLength() ) ) );
		int widthQ = Math.max( 2, Math.min( 16, getWindowSize( l.bitLength() ) ) );

		P.precomputeWNaf( widthP );
		Q.precomputeWNaf( widthQ );

		ECPoint[] preCompP = negK ? P.preCompWNafNeg : P.preCompWNaf;
		ECPoint[] preCompQ = negL ? Q.preCompWNafNeg : Q.preCompWNaf;
		ECPoint[] preCompNegP = negK ? P.preCompWNaf : P.preCompWNafNeg;
		ECPoint[] preCompNegQ = negL ? Q.preCompWNaf : Q.preCompWNafNeg;

		byte[] wnafP = generateWindowNaf( widthP, k );
		byte[] wnafQ = generateWindowNaf( widthQ, l );

		return implShamirsTrickWNaf( preCompP, preCompNegP, wnafP, preCompQ, preCompNegQ, wnafQ );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static ECPoint implShamirsTrickWNaf( ECPoint[] preCompP, ECPoint[] preCompNegP, byte[] wnafP,
			ECPoint[] preCompQ, ECPoint[] preCompNegQ, byte[] wnafQ )
	{
		int len = Math.max( wnafP.length, wnafQ.length );

		ECCurve curve = preCompP[ 0 ].getCurve();
		ECPoint infinity = curve.getInfinity();

		ECPoint R = infinity;
		int zeroes = 0;

		for( int i = len - 1; i >= 0; --i )
		{
			int wiP = i < wnafP.length ? wnafP[ i ] : 0;
			int wiQ = i < wnafQ.length ? wnafQ[ i ] : 0;

			if( (wiP | wiQ) == 0 )
			{
				++zeroes;
				continue;
			}

			ECPoint r = infinity;
			if( wiP != 0 )
			{
				int nP = Math.abs( wiP );
				ECPoint[] tableP = wiP < 0 ? preCompNegP : preCompP;
				r = r.add( tableP[ nP >>> 1 ] );
			}
			if( wiQ != 0 )
			{
				int nQ = Math.abs( wiQ );
				ECPoint[] tableQ = wiQ < 0 ? preCompNegQ : preCompQ;
				r = r.add( tableQ[ nQ >>> 1 ] );
			}

			if( zeroes > 0 )
			{
				R = R.timesPow2( zeroes );
				zeroes = 0;
			}

			R = R.twicePlus( r );
		}

		if( zeroes > 0 )
		{
			R = R.timesPow2( zeroes );
		}

		return R;
	}


	// =================================================================================================================
	// POINT
	// =================================================================================================================

	/**
	 * base class for points on elliptic curves.
	 */
	public abstract class ECPoint
	{
		public final ECElement x;
		public final ECElement y;
		public final ECElement[] zs;

		private ECPoint[] preComputedComb = null;
		private ECPoint preComputedCombOffset = null;
		private int preComputedCombWidth = 0; // number of bits

		private ECPoint[] preCompWNaf = null;
		private ECPoint[] preCompWNafNeg = null;


		protected ECPoint( ECElement x, ECElement y, ECElement[] zs )
		{
			MUST( (x == null) == (y == null) );
			this.x = x;
			this.y = y;
			this.zs = zs;
		}


		protected abstract ECPoint create( ECElement x, ECElement y );
		protected abstract ECPoint create( ECElement x, ECElement y, ECElement[] zs );


		protected abstract boolean satisfiesCurveEquation();


		protected boolean satisfiesOrder()
		{
			if( getCofactor().equals( BigInteger.ONE ) )
			{
				return true;
			}

			return referenceMultiply( getOrder() ).isInfinity();
		}

		public ECCurve getCurve()
		{
			return ECCurve.this;
		}

		/**
		 * Returns the affine x-coordinate after checking that this point is normalized.
		 */
		public ECElement getAffineXCoord()
		{
			MUST( isNormalized() );
			return getXCoord();
		}

		/**
		 * Returns the affine y-coordinate after checking that this point is normalized
		 */
		public ECElement getAffineYCoord()
		{
			MUST( isNormalized() );
			return getYCoord();
		}

		/**
		 * Returns the x-coordinate.
		 * 
		 * Caution: depending on the curve's coordinate system, this may not be the same value as in an
		 * affine coordinate system; use normalize() to get a point where the coordinates have their
		 * affine values, or use getAffineXCoord() if you expect the point to already have been
		 * normalized.
		 * 
		 * @return the x-coordinate of this point
		 */
		public ECElement getXCoord()
		{
			return x;
		}

		/**
		 * Returns the y-coordinate.
		 * 
		 * Caution: depending on the curve's coordinate system, this may not be the same value as in an
		 * affine coordinate system; use normalize() to get a point where the coordinates have their
		 * affine values, or use getAffineYCoord() if you expect the point to already have been
		 * normalized.
		 * 
		 * @return the y-coordinate of this point
		 */
		public ECElement getYCoord()
		{
			return y;
		}

		public ECElement getZCoord( int index )
		{
			return (index < 0 || index >= zs.length) ? null : zs[ index ];
		}

		public final ECElement getRawXCoord()
		{
			return x;
		}

		public final ECElement getRawYCoord()
		{
			return y;
		}

		protected final ECElement[] getRawZCoords()
		{
			return zs;
		}

		public boolean isNormalized()
		{
			return isInfinity() || zs[ 0 ].isOne();
		}

		/**
		 * Normalization ensures that any projective coordinate is 1, and therefore that the x, y
		 * coordinates reflect those of the equivalent point in an affine coordinate system.
		 * @return a new ECPoint instance representing the same point, but with normalized coordinates
		 */
		public abstract ECPoint normalize();

		public boolean isInfinity()
		{
			return x == null || y == null || (zs.length > 0 && zs[ 0 ].isZero());
		}
		
		public boolean isValid()
		{
			if( isInfinity() )
			{
				return true;
			}
			return satisfiesCurveEquation() && satisfiesOrder();
		}

		public boolean equals( ECPoint other )
		{
			if( other == null )
			{
				return false;
			}

			ECCurve c1 = this.getCurve();
			ECCurve c2 = other.getCurve();
			boolean i1 = isInfinity(), i2 = other.isInfinity();

			if( i1 || i2 )
			{
				return i1 && i2 && c1.equals( c2 );
			}

			ECPoint p2 = other.normalize();
			ECPoint p1 = normalize();
			p2 = c1.importPoint( p2 ).normalize();

			return p1.getXCoord().equals( p2.getXCoord() ) && p1.getYCoord().equals( p2.getYCoord() );
		}

		@Override
		public boolean equals( Object other )
		{
			if( other == this )
			{
				return true;
			}

			if( !(other instanceof ECPoint) )
			{
				return false;
			}

			return equals( (ECPoint)other );
		}

		@Override
		public int hashCode()
		{
			ECCurve c = this.getCurve();
			int hc = (null == c) ? 0 : ~c.hashCode();

			if( !this.isInfinity() )
			{
				ECPoint p = normalize();
				hc ^= p.getXCoord().hashCode() * 17;
				hc ^= p.getYCoord().hashCode() * 257;
			}

			return hc;
		}

		/**
		 * Get an encoding of the point value, optionally in compressed format.
		 * @param compressed whether to generate a compressed point encoding.
		 */
		public Binary getEncoded( boolean compressed )
		{
			if( this.isInfinity() )
			{
				return Bin( 1 );
			}

			ECPoint normed = normalize();

			Binary X = normed.getXCoord().toBin();

			if( compressed )
			{
				Binary res = Bin().reserve( X.size() + 1 );
				res.add( normed.getCompressionYTilde() ? 0x03 : 0x02 );
				res.add( X );
				return res;
			}

			Binary res = Bin().reserve( X.size() * 2 + 1 );
			res.add( 0x04 );
			res.add( X );
			res.add( normed.getYCoord().toBin() );
			return res;
		}

		protected abstract boolean getCompressionYTilde();

		public abstract ECPoint add( ECPoint b );

		public abstract ECPoint negate();


		public final ECPoint subtract( ECPoint b )
		{
			if( b.isInfinity() )
			{
				return this;
			}

			// Add -b
			return this.add( b.negate() );
		}


		public ECPoint timesPow2( int e )
		{
			MUST( e >= 0, "'e' cannot be negative" );

			ECPoint p = this;
			while( --e >= 0 )
			{
				p = p.twice();
			}
			return p;
		}


		public abstract ECPoint twice();


		// -----------------------------------------------------------------------------------------------------------------
		public ECPoint twicePlus( ECPoint b )
		{
			if( this.isInfinity() )
			{
				return b;
			}
			if( b.isInfinity() )
			{
				return twice();
			}

			ECElement Y1 = this.y;
			if( Y1.isZero() )
			{
				return b;
			}

			return twice().add( b );
		}

		// =================================================================================================================

		/**
		 * Simple shift-and-add multiplication. Serves as reference implementation to verify implementations,
		 * and for very small scalars.
		 * @return k * P.
		 */
		public ECPoint referenceMultiply( BigInteger k )
		{
			BigInteger x = k.abs();
			ECPoint q = getInfinity();
			ECPoint p = this;
			int t = x.bitLength();
			if( t > 0 )
			{
				if( x.testBit( 0 ) )
				{
					q = p;
				}
				for( int i = 1; i < t; i++ )
				{
					p = p.twice();
					if( x.testBit( i ) )
					{
						q = q.add( p );
					}
				}
			}
			return k.signum() < 0 ? q.negate() : q;
		}


		// =================================================================================================================

		// -----------------------------------------------------------------------------------------------------------------
		private int getCombSize()
		{
			BigInteger order = getOrder();
			return (order == null) ? (getFieldSize() + 1) : order.bitLength();
		}

		// -----------------------------------------------------------------------------------------------------------------
		private void precomputeMultComb()
		{
			if( preComputedComb != null )
				return;

			int bits = getCombSize();
			int width = bits > 257 ? 6 : 5;
			int n = 1 << width;

			int d = (bits + width - 1) / width;

			ECPoint[] pow2Table = new ECPoint[ width + 1 ];
			pow2Table[ 0 ] = normalize();
			for( int i = 1; i < width; ++i )
			{
				pow2Table[ i ] = pow2Table[ i - 1 ].timesPow2( d ).normalize();
			}
			pow2Table[ width ] = pow2Table[ 0 ].subtract( pow2Table[ 1 ] ).normalize();

			ECPoint[] points = new ECPoint[ n ];
			points[ 0 ] = pow2Table[ 0 ];
			for( int bit = width - 1; bit >= 0; --bit )
			{
				ECPoint pow2 = pow2Table[ bit ];
				int step = 1 << bit;
				for( int i = step; i < n; i += (step << 1) )
				{
					points[ i ] = points[ i - step ].add( pow2 ).normalize();
				}
			}

			preComputedComb = points;
			preComputedCombWidth = width;
			preComputedCombOffset = pow2Table[ width ];
		}

		// -----------------------------------------------------------------------------------------------------------------
		/**
		 * Multiplies the 'ECPoint p' by 'k', i.e. 'p' is added 'k' times to itself.
		 * @return 'p' multiplied by 'k'.
		 */
		ECPoint multiplyComb( BigInteger k )
		{
			int sign = k.signum();
			if( sign == 0 || isInfinity() )
			{
				return getInfinity();
			}

			k = k.abs();
			int size = getCombSize();
			MUST( k.bitLength() <= size, "fixed-point comb doesn't support scalars larger than the curve order" );

			precomputeMultComb();

			int d = (size + preComputedCombWidth - 1) / preComputedCombWidth;

			ECPoint R = getInfinity();

			int fullComb = d * preComputedCombWidth;
			int[] K = Nat.fromBigInteger( fullComb, k );

			int top = fullComb - 1;
			for( int i = 0; i < d; ++i )
			{
				int index = 0;
				for( int j = top - i; j >= 0; j -= d )
				{
					index <<= 1;
					index |= Nat.getBit( K, j );
				}
				ECPoint add = preComputedComb[ index ]; 
				R = R.twicePlus( add );
			}

			R = R.add( preComputedCombOffset );
			return (sign > 0) ? R : R.negate();
		}

		// -----------------------------------------------------------------------------------------------------------------
		/**
		 * Multiplies this 'ECPoint' by an integer 'k' using the Window NAF method.
		 */
		public ECPoint multiply( BigInteger k )
		{
			int sign = k.signum();
			if( sign == 0 || isInfinity() )
			{
				return getInfinity();
			}
			k = k.abs();
			
			// Clamp the window width in the range [2, 16]
			int width = Math.max( 2, Math.min( 16, getWindowSize( k.bitLength() ) ) );

			precomputeWNaf( width );
			int[] wnaf = generateCompactWindowNaf( width, k );

			ECPoint R = getInfinity();

			int i = wnaf.length;

			// NOTE: We try to optimize the first window using the precomputed points to substitute an
			// addition for 2 or more doublings.
			if( i > 1 )
			{
				int wi = wnaf[ --i ];
				int digit = wi >> 16, zeroes = wi & 0xFFFF;

				int n = Math.abs( digit );
				ECPoint[] table = digit < 0 ? preCompWNafNeg : preCompWNaf;

				// Optimization can only be used for values in the lower half of the table
				if( (n << 2) < (1 << width) )
				{
					int highest = (Integer.SIZE - Integer.numberOfLeadingZeros( n ));

					int scale = width - highest;
					int lowBits = n ^ (1 << (highest - 1));

					int i1 = ((1 << (width - 1)) - 1);
					int i2 = (lowBits << scale) + 1;
					R = table[ i1 >>> 1 ].add( table[ i2 >>> 1 ] );

					zeroes -= scale;
				}
				else
				{
					R = table[ n >>> 1 ];
				}

				R = R.timesPow2( zeroes );
			}

			while( i > 0 )
			{
				int wi = wnaf[ --i ];
				int digit = wi >> 16, zeroes = wi & 0xFFFF;

				int n = Math.abs( digit );
				ECPoint[] table = digit < 0 ? preCompWNafNeg : preCompWNaf;
				ECPoint r = table[ n >>> 1 ];

				R = R.twicePlus( r );
				R = R.timesPow2( zeroes );
			}

			return (sign > 0) ? R : R.negate();
		}

		// -----------------------------------------------------------------------------------------------------------------
		private void precomputeWNaf( final int width )
		{
			int reqPreCompLen = 1 << Math.max( 0, width - 2 );

			if( (preCompWNaf != null) && (preCompWNaf.length >= reqPreCompLen)
				&& (preCompWNafNeg != null) && (preCompWNafNeg.length >= reqPreCompLen) )
			{
				return;
			}

			int iniPreCompLen = 0;
			if( preCompWNaf == null )
			{
				preCompWNaf = new ECPoint[0];
			}
			else
			{
				iniPreCompLen = preCompWNaf.length;
			}

			if( iniPreCompLen < reqPreCompLen )
			{
				preCompWNaf = resizeTable( preCompWNaf, reqPreCompLen );

				if( reqPreCompLen == 1 )
				{
					preCompWNaf[ 0 ] = normalize();
				}
				else
				{
					int curPreCompLen = iniPreCompLen;
					if( curPreCompLen == 0 )
					{
						preCompWNaf[ 0 ] = normalize();
						curPreCompLen = 1;
					}

					ECPoint twiceP = preCompWNaf[ 0 ].twice();
					
					if( reqPreCompLen == 2 )
					{
						preCompWNaf[ 1 ] = twiceP.add( this ).normalize();
					}
					else
					{
						ECPoint last = preCompWNaf[ curPreCompLen - 1 ];
						while( curPreCompLen < reqPreCompLen )
						{
							// Compute the new ECPoints for the precomputation array. The values
							// 1, 3, 5, ..., 2^(width-1)-1 times p are computed
							last = last.add( twiceP ).normalize();
							preCompWNaf[ curPreCompLen++ ] = last;
						}
					}
				}
			}

			int pos;
			if( preCompWNafNeg == null )
			{
				pos = 0;
				preCompWNafNeg = new ECPoint[ reqPreCompLen ];
			}
			else
			{
				pos = preCompWNafNeg.length;
				if( pos < reqPreCompLen )
				{
					preCompWNafNeg = resizeTable( preCompWNafNeg, reqPreCompLen );
				}
			}

			while( pos < reqPreCompLen )
			{
				preCompWNafNeg[ pos ] = preCompWNaf[ pos ].negate();
				++pos;
			}
		}

	} // ECPoint


	// =================================================================================================================
	// ELEMENT
	// =================================================================================================================

	/**
	 * Field Element
	 */
	public abstract class ECElement
	{
		public Binary toBin()
		{
			int len = (getFieldSize() + 7) / 8;
			return ECCurve.BigInt2Bin( len, toBigInteger() );
		}

		public abstract ECElement create( BigInteger x );

		public abstract BigInteger toBigInteger();

		public abstract int getFieldSize();

		public abstract ECElement add( ECElement b );

		public abstract ECElement addOne();

		public abstract ECElement subtract( ECElement b );

		public abstract ECElement multiply( ECElement b );

		public abstract ECElement divide( ECElement b );

		public abstract ECElement negate();

		public abstract ECElement square();

		public abstract ECElement invert();

		public abstract ECElement sqrt();

		public int bitLength()
		{
			return toBigInteger().bitLength();
		}

		public boolean isOne()
		{
			return bitLength() == 1;
		}

		public boolean isZero()
		{
			return 0 == toBigInteger().signum();
		}

		public ECElement multiplyPlusProduct( ECElement b, ECElement x, ECElement y )
		{
			return multiply( b ).add( x.multiply( y ) );
		}

		public ECElement squarePlusProduct( ECElement x, ECElement y )
		{
			return square().add( x.multiply( y ) );
		}

		public ECElement squarePow( int pow )
		{
			ECElement r = this;
			for( int i = 0; i < pow; ++i )
			{
				r = r.square();
			}
			return r;
		}

		public boolean testBitZero()
		{
			return toBigInteger().testBit( 0 );
		}

	} // ECElement
}
