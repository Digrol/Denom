package org.denom.crypt.ec;

import java.math.BigInteger;
import java.util.Random;

import static org.denom.Ex.MUST;

public abstract class Nat
{
	private static final long M = 0xFFFFFFFFL;

	public static int add( int len, int[] x, int[] y, int[] z )
	{
		long c = 0;
		for( int i = 0; i < len; ++i )
		{
			c += (x[ i ] & M) + (y[ i ] & M);
			z[ i ] = (int)c;
			c >>>= 32;
		}
		return (int)c;
	}

	public static int add33To( int len, int x, int[] z )
	{
		long c = (z[ 0 ] & M) + (x & M);
		z[ 0 ] = (int)c;
		c >>>= 32;
		c += (z[ 1 ] & M) + 1L;
		z[ 1 ] = (int)c;
		c >>>= 32;
		return c == 0 ? 0 : incAt( len, z, 2 );
	}

	public static int addBothTo( int len, int[] x, int[] y, int[] z )
	{
		long c = 0;
		for( int i = 0; i < len; ++i )
		{
			c += (x[ i ] & M) + (y[ i ] & M) + (z[ i ] & M);
			z[ i ] = (int)c;
			c >>>= 32;
		}
		return (int)c;
	}

	public static int addTo( int len, int[] x, int[] z )
	{
		long c = 0;
		for( int i = 0; i < len; ++i )
		{
			c += (x[ i ] & M) + (z[ i ] & M);
			z[ i ] = (int)c;
			c >>>= 32;
		}
		return (int)c;
	}

	public static int addTo( int len, int[] x, int xOff, int[] z, int zOff )
	{
		long c = 0;
		for( int i = 0; i < len; ++i )
		{
			c += (x[ xOff + i ] & M) + (z[ zOff + i ] & M);
			z[ zOff + i ] = (int)c;
			c >>>= 32;
		}
		return (int)c;
	}

	public static int addWordAt( int len, int x, int[] z, int zPos )
	{
		// assert zPos <= (len - 1);
		long c = (x & M) + (z[ zPos ] & M);
		z[ zPos ] = (int)c;
		c >>>= 32;
		return c == 0 ? 0 : incAt( len, z, zPos + 1 );
	}

	public static int addWordAt( int len, int x, int[] z, int zOff, int zPos )
	{
		// assert zPos <= (len - 1);
		long c = (x & M) + (z[ zOff + zPos ] & M);
		z[ zOff + zPos ] = (int)c;
		c >>>= 32;
		return c == 0 ? 0 : incAt( len, z, zOff, zPos + 1 );
	}

	public static int addWordTo( int len, int x, int[] z )
	{
		long c = (x & M) + (z[ 0 ] & M);
		z[ 0 ] = (int)c;
		c >>>= 32;
		return c == 0 ? 0 : incAt( len, z, 1 );
	}

	public static int cadd( int len, int mask, int[] x, int[] y, int[] z )
	{
		long MASK = -(mask & 1) & M;
		long c = 0;
		for( int i = 0; i < len; ++i )
		{
			c += (x[ i ] & M) + (y[ i ] & MASK);
			z[ i ] = (int)c;
			c >>>= 32;
		}
		return (int)c;
	}

	public static void cmov( int len, int mask, int[] x, int xOff, int[] z, int zOff )
	{
		mask = -(mask & 1);

		for( int i = 0; i < len; ++i )
		{
			int z_i = z[ zOff + i ], diff = z_i ^ x[ xOff + i ];
			z_i ^= (diff & mask);
			z[ zOff + i ] = z_i;
		}
	}

	public static int[] copy( int len, int[] x )
	{
		int[] z = new int[ len ];
		System.arraycopy( x, 0, z, 0, len );
		return z;
	}

	public static void copy( int len, int[] x, int[] z )
	{
		System.arraycopy( x, 0, z, 0, len );
	}


	public static int dec( int len, int[] z )
	{
		for( int i = 0; i < len; ++i )
		{
			if( --z[ i ] != -1 )
			{
				return 0;
			}
		}
		return -1;
	}


	public static int decAt( int len, int[] z, int zPos )
	{
		// assert zPos <= len;
		for( int i = zPos; i < len; ++i )
		{
			if( --z[ i ] != -1 )
			{
				return 0;
			}
		}
		return -1;
	}

	public static int decAt( int len, int[] z, int zOff, int zPos )
	{
		// assert zPos <= len;
		for( int i = zPos; i < len; ++i )
		{
			if( --z[ zOff + i ] != -1 )
			{
				return 0;
			}
		}
		return -1;
	}

	public static int[] fromBigInteger( int bitLen, BigInteger x )
	{
		MUST( (x.signum() >= 0) && (x.bitLength() <= bitLen) );

		int len = (bitLen + 31) >> 5;
		int[] z = new int[ len ];
		int i = 0;
		while( x.signum() != 0 )
		{
			z[ i++ ] = x.intValue();
			x = x.shiftRight( 32 );
		}
		return z;
	}
	
	public static long[] fromBigInteger64( int bitLen, BigInteger x )
	{
		MUST( (x.signum() >= 0) && (x.bitLength() <= bitLen) );

		int len = (bitLen + 63) >> 6;
		long[] z = new long[ len ];
		int i = 0;
		while( x.signum() != 0 )
		{
			z[ i++ ] = x.longValue();
			x = x.shiftRight( 64 );
		}
		return z;
	}


	public static int getBit( int[] x, int bit )
	{
		if( bit == 0 )
		{
			return x[ 0 ] & 1;
		}
		int w = bit >> 5;
		if( w < 0 || w >= x.length )
		{
			return 0;
		}
		int b = bit & 31;
		return (x[ w ] >>> b) & 1;
	}

	public static boolean gte( int len, int[] x, int[] y )
	{
		for( int i = len - 1; i >= 0; --i )
		{
			int x_i = x[ i ] ^ Integer.MIN_VALUE;
			int y_i = y[ i ] ^ Integer.MIN_VALUE;
			if( x_i < y_i )
				return false;
			if( x_i > y_i )
				return true;
		}
		return true;
	}

	public static int inc( int len, int[] z )
	{
		for( int i = 0; i < len; ++i )
		{
			if( ++z[ i ] != 0 )
			{
				return 0;
			}
		}
		return 1;
	}

	public static int inc( int len, int[] x, int[] z )
	{
		int i = 0;
		while( i < len )
		{
			int c = x[ i ] + 1;
			z[ i ] = c;
			++i;
			if( c != 0 )
			{
				while( i < len )
				{
					z[ i ] = x[ i ];
					++i;
				}
				return 0;
			}
		}
		return 1;
	}

	public static int incAt( int len, int[] z, int zPos )
	{
		// assert zPos <= len;
		for( int i = zPos; i < len; ++i )
		{
			if( ++z[ i ] != 0 )
			{
				return 0;
			}
		}
		return 1;
	}

	public static int incAt( int len, int[] z, int zOff, int zPos )
	{
		// assert zPos <= len;
		for( int i = zPos; i < len; ++i )
		{
			if( ++z[ zOff + i ] != 0 )
			{
				return 0;
			}
		}
		return 1;
	}

	public static boolean isOne( int len, int[] x )
	{
		if( x[ 0 ] != 1 )
		{
			return false;
		}
		for( int i = 1; i < len; ++i )
		{
			if( x[ i ] != 0 )
			{
				return false;
			}
		}
		return true;
	}

	public static boolean isOne64( long[] x )
	{
		if( x[ 0 ] != 1 )
		{
			return false;
		}
		int len = x.length;
		for( int i = 1; i < len; ++i )
		{
			if( x[ i ] != 0 )
			{
				return false;
			}
		}
		return true;
	}

	public static boolean isZero( int len, int[] x )
	{
		for( int i = 0; i < len; ++i )
		{
			if( x[ i ] != 0 )
			{
				return false;
			}
		}
		return true;
	}

	public static boolean isZero64( long[] x )
	{
		int len = x.length;
		for( int i = 0; i < len; ++i )
		{
			if( x[ i ] != 0 )
			{
				return false;
			}
		}
		return true;
	}

	public static void mul( int len, int[] x, int[] y, int[] zz )
	{
		zz[ len ] = mulWord( len, x[ 0 ], y, zz );

		for( int i = 1; i < len; ++i )
		{
			zz[ i + len ] = mulWordAddTo( len, x[ i ], y, 0, zz, i );
		}
	}

	public static int mulAddTo( int len, int[] x, int[] y, int[] zz )
	{
		long zc = 0;
		for( int i = 0; i < len; ++i )
		{
			long c = mulWordAddTo( len, x[ i ], y, 0, zz, i ) & M;
			c += zc + (zz[ i + len ] & M);
			zz[ i + len ] = (int)c;
			zc = c >>> 32;
		}
		return (int)zc;
	}


	public static long mul33Add( int len, int w, int[] x, int xOff, int[] y, int yOff, int[] z, int zOff )
	{
		long wVal = w & M;
		long c = 0;
		long xPrev = 0;
		for( int i = 0; i < len; ++i )
		{
			long xi = x[ xOff++ ] & M;
			c += wVal * xi + xPrev + (y[ yOff++ ] & M);
			xPrev = xi;
			z[ zOff++ ] = (int)c;
			c >>>= 32;
		}
		c += xPrev;
		return c;
	}

	public static int mul33DWordAdd( int len, int x, long y, int[] z, int zOff )
	{
		long c = 0, xVal = x & M;
		long y00 = y & M;
		c += xVal * y00 + (z[ zOff + 0 ] & M);
		z[ zOff + 0 ] = (int)c;
		c >>>= 32;
		long y01 = y >>> 32;
		c += xVal * y01 + y00 + (z[ zOff + 1 ] & M);
		z[ zOff + 1 ] = (int)c;
		c >>>= 32;
		c += y01 + (z[ zOff + 2 ] & M);
		z[ zOff + 2 ] = (int)c;
		c >>>= 32;
		c += (z[ zOff + 3 ] & M);
		z[ zOff + 3 ] = (int)c;
		c >>>= 32;
		return c == 0 ? 0 : Nat.incAt( len, z, zOff, 4 );
	}

	public static int mul33WordAdd( int len, int x, int y, int[] z, int zOff )
	{
		long c = 0, xVal = x & M, yVal = y & M;
		c += yVal * xVal + (z[ zOff + 0 ] & M);
		z[ zOff + 0 ] = (int)c;
		c >>>= 32;
		c += yVal + (z[ zOff + 1 ] & M);
		z[ zOff + 1 ] = (int)c;
		c >>>= 32;
		c += (z[ zOff + 2 ] & M);
		z[ zOff + 2 ] = (int)c;
		c >>>= 32;
		return c == 0 ? 0 : Nat.incAt( len, z, zOff, 3 );
	}

	public static int mulWordsAdd( int len, int x, int y, int[] z )
	{
		long c = 0, xVal = x & M, yVal = y & M;
		c += yVal * xVal + (z[ 0 ] & M);
		z[ 0 ] = (int)c;
		c >>>= 32;
		c += (z[ 1 ] & M);
		z[ 1 ] = (int)c;
		c >>>= 32;
		return c == 0 ? 0 : Nat.incAt( len, z, 0, 2 );
	}

	public static int mulWord( int len, int x, int[] y, int[] z )
	{
		long c = 0, xVal = x & M;
		int i = 0;
		do
		{
			c += xVal * (y[ i ] & M);
			z[ i ] = (int)c;
			c >>>= 32;
		}
		while( ++i < len );
		return (int)c;
	}


	public static int mulWordAddTo( int len, int x, int[] y, int yOff, int[] z, int zOff )
	{
		long c = 0, xVal = x & M;
		int i = 0;
		do
		{
			c += xVal * (y[ yOff + i ] & M) + (z[ zOff + i ] & M);
			z[ zOff + i ] = (int)c;
			c >>>= 32;
		}
		while( ++i < len );
		return (int)c;
	}

	public static int shiftDownBit( int len, int[] z, int c )
	{
		int i = len;
		while( --i >= 0 )
		{
			int next = z[ i ];
			z[ i ] = (next >>> 1) | (c << 31);
			c = next;
		}
		return c << 31;
	}

	public static int shiftDownBits( int len, int[] z, int bits, int c )
	{
		//        assert bits > 0 && bits < 32;
		int i = len;
		while( --i >= 0 )
		{
			int next = z[ i ];
			z[ i ] = (next >>> bits) | (c << -bits);
			c = next;
		}
		return c << -bits;
	}


	public static int shiftDownBits( int len, int[] x, int xOff, int bits, int c, int[] z, int zOff )
	{
		//        assert bits > 0 && bits < 32;
		int i = len;
		while( --i >= 0 )
		{
			int next = x[ xOff + i ];
			z[ zOff + i ] = (next >>> bits) | (c << -bits);
			c = next;
		}
		return c << -bits;
	}

	public static int shiftDownWord( int len, int[] z, int c )
	{
		int i = len;
		while( --i >= 0 )
		{
			int next = z[ i ];
			z[ i ] = c;
			c = next;
		}
		return c;
	}

	public static int shiftUpBit( int len, int[] z, int c )
	{
		for( int i = 0; i < len; ++i )
		{
			int next = z[ i ];
			z[ i ] = (next << 1) | (c >>> 31);
			c = next;
		}
		return c >>> 31;
	}

	public static int shiftUpBit( int len, int[] z, int zOff, int c )
	{
		for( int i = 0; i < len; ++i )
		{
			int next = z[ zOff + i ];
			z[ zOff + i ] = (next << 1) | (c >>> 31);
			c = next;
		}
		return c >>> 31;
	}

	public static int shiftUpBit( int len, int[] x, int c, int[] z )
	{
		for( int i = 0; i < len; ++i )
		{
			int next = x[ i ];
			z[ i ] = (next << 1) | (c >>> 31);
			c = next;
		}
		return c >>> 31;
	}

	public static int shiftUpBit( int len, int[] x, int xOff, int c, int[] z, int zOff )
	{
		for( int i = 0; i < len; ++i )
		{
			int next = x[ xOff + i ];
			z[ zOff + i ] = (next << 1) | (c >>> 31);
			c = next;
		}
		return c >>> 31;
	}

	public static int shiftUpBits( int len, int[] z, int bits, int c )
	{
		//        assert bits > 0 && bits < 32;
		for( int i = 0; i < len; ++i )
		{
			int next = z[ i ];
			z[ i ] = (next << bits) | (c >>> -bits);
			c = next;
		}
		return c >>> -bits;
	}

	public static int shiftUpBits( int len, int[] x, int bits, int c, int[] z )
	{
		//        assert bits > 0 && bits < 32;
		for( int i = 0; i < len; ++i )
		{
			int next = x[ i ];
			z[ i ] = (next << bits) | (c >>> -bits);
			c = next;
		}
		return c >>> -bits;
	}

	public static void square( int len, int[] x, int[] zz )
	{
		int extLen = len << 1;
		int c = 0;
		int j = len, k = extLen;
		do
		{
			long xVal = (x[ --j ] & M);
			long p = xVal * xVal;
			zz[ --k ] = (c << 31) | (int)(p >>> 33);
			zz[ --k ] = (int)(p >>> 1);
			c = (int)p;
		}
		while( j > 0 );

		for( int i = 1; i < len; ++i )
		{
			c = squareWordAdd( x, i, zz );
			addWordAt( extLen, c, zz, i << 1 );
		}

		shiftUpBit( extLen, zz, x[ 0 ] << 31 );
	}

	public static void square( int len, int[] x, int xOff, int[] zz, int zzOff )
	{
		int extLen = len << 1;
		int c = 0;
		int j = len, k = extLen;
		do
		{
			long xVal = (x[ xOff + --j ] & M);
			long p = xVal * xVal;
			zz[ zzOff + --k ] = (c << 31) | (int)(p >>> 33);
			zz[ zzOff + --k ] = (int)(p >>> 1);
			c = (int)p;
		}
		while( j > 0 );

		for( int i = 1; i < len; ++i )
		{
			c = squareWordAdd( x, xOff, i, zz, zzOff );
			addWordAt( extLen, c, zz, zzOff, i << 1 );
		}

		shiftUpBit( extLen, zz, zzOff, x[ xOff ] << 31 );
	}

	public static int squareWordAdd( int[] x, int xPos, int[] z )
	{
		long c = 0, xVal = x[ xPos ] & M;
		int i = 0;
		do
		{
			c += xVal * (x[ i ] & M) + (z[ xPos + i ] & M);
			z[ xPos + i ] = (int)c;
			c >>>= 32;
		}
		while( ++i < xPos );
		return (int)c;
	}

	public static int squareWordAdd( int[] x, int xOff, int xPos, int[] z, int zOff )
	{
		long c = 0, xVal = x[ xOff + xPos ] & M;
		int i = 0;
		do
		{
			c += xVal * (x[ xOff + i ] & M) + (z[ xPos + zOff ] & M);
			z[ xPos + zOff ] = (int)c;
			c >>>= 32;
			++zOff;
		}
		while( ++i < xPos );
		return (int)c;
	}

	public static int sub( int len, int[] x, int[] y, int[] z )
	{
		long c = 0;
		for( int i = 0; i < len; ++i )
		{
			c += (x[ i ] & M) - (y[ i ] & M);
			z[ i ] = (int)c;
			c >>= 32;
		}
		return (int)c;
	}

	public static int sub( int len, int[] x, int xOff, int[] y, int yOff, int[] z, int zOff )
	{
		long c = 0;
		for( int i = 0; i < len; ++i )
		{
			c += (x[ xOff + i ] & M) - (y[ yOff + i ] & M);
			z[ zOff + i ] = (int)c;
			c >>= 32;
		}
		return (int)c;
	}

	public static int sub33From( int len, int x, int[] z )
	{
		long c = (z[ 0 ] & M) - (x & M);
		z[ 0 ] = (int)c;
		c >>= 32;
		c += (z[ 1 ] & M) - 1;
		z[ 1 ] = (int)c;
		c >>= 32;
		return c == 0 ? 0 : decAt( len, z, 2 );
	}

	public static int subFrom( int len, int[] x, int[] z )
	{
		long c = 0;
		for( int i = 0; i < len; ++i )
		{
			c += (z[ i ] & M) - (x[ i ] & M);
			z[ i ] = (int)c;
			c >>= 32;
		}
		return (int)c;
	}

	public static int subFrom( int len, int[] x, int xOff, int[] z, int zOff )
	{
		long c = 0;
		for( int i = 0; i < len; ++i )
		{
			c += (z[ zOff + i ] & M) - (x[ xOff + i ] & M);
			z[ zOff + i ] = (int)c;
			c >>= 32;
		}
		return (int)c;
	}

	public static int subWordFrom( int len, int x, int[] z )
	{
		long c = (z[ 0 ] & M) - (x & M);
		z[ 0 ] = (int)c;
		c >>= 32;
		return c == 0 ? 0 : decAt( len, z, 1 );
	}


	public static void intToBigEndian( int n, byte[] bs, int off )
	{
		bs[ off ] = (byte)(n >>> 24);
		bs[ ++off ] = (byte)(n >>> 16);
		bs[ ++off ] = (byte)(n >>> 8);
		bs[ ++off ] = (byte)(n);
	}

	public static BigInteger toBigInteger( int len, int[] x )
	{
		byte[] bs = new byte[ len << 2 ];
		for( int i = 0; i < len; ++i )
		{
			int xI = x[ i ];
			if( xI != 0 )
			{
				intToBigEndian( xI, bs, (len - 1 - i) << 2 );
			}
		}
		return new BigInteger( 1, bs );
	}

	public static BigInteger toBigInteger64( long[] x )
	{
		int len = x.length;
		byte[] bs = new byte[ len << 3 ];
		for( int i = 0; i < len; ++i )
		{
			long xI = x[ i ];
			if( xI != 0 )
			{
				int offset = (len - 1 - i) << 3;
				intToBigEndian( (int)(xI >>> 32), bs, offset );
				intToBigEndian( (int)(xI & 0xffffffffL), bs, offset + 4 );
			}
		}
		return new BigInteger( 1, bs );
	}

	public static void zero( int len, int[] z )
	{
		for( int i = 0; i < len; ++i )
		{
			z[ i ] = 0;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static int[] random( int[] p )
	{
		int len = p.length;
		Random rand = new Random();
		int[] s = new int[ len ];

		int m = p[ len - 1 ];
		m |= m >>> 1;
		m |= m >>> 2;
		m |= m >>> 4;
		m |= m >>> 8;
		m |= m >>> 16;

		do
		{
			for( int i = 0; i != len; i++ )
			{
				s[ i ] = rand.nextInt();
			}
			s[ len - 1 ] &= m;
		}
		while( Nat.gte( len, s, p ) );

		return s;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void inversionResult( int[] p, int ac, int[] a, int[] z )
	{
		if( ac < 0 )
		{
			Nat.add( p.length, a, p, z );
		}
		else
		{
			System.arraycopy( a, 0, z, 0, p.length );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static int inversionStep( int[] p, int[] u, int uLen, int[] x, int xc )
	{
		int len = p.length;
		int count = 0;
		while( u[ 0 ] == 0 )
		{
			Nat.shiftDownWord( uLen, u, 0 );
			count += 32;
		}

		{
			int zeroes = getTrailingZeroes( u[ 0 ] );
			if( zeroes > 0 )
			{
				Nat.shiftDownBits( uLen, u, zeroes, 0 );
				count += zeroes;
			}
		}

		for( int i = 0; i < count; ++i )
		{
			if( (x[ 0 ] & 1) != 0 )
			{
				if( xc < 0 )
				{
					xc += Nat.addTo( len, p, x );
				}
				else
				{
					xc += Nat.subFrom( len, p, x );
				}
			}

			Nat.shiftDownBit( len, x, xc );
		}

		return xc;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static int getTrailingZeroes( int x )
	{
		int count = 0;
		while( (x & 1) == 0 )
		{
			x >>>= 1;
			++count;
		}
		return count;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void invert( int[] p, int[] x, int[] z )
	{
		int len = p.length;
		MUST( !Nat.isZero( len, x ), "'x' cannot be 0" );

		if( Nat.isOne( len, x ) )
		{
			System.arraycopy( x, 0, z, 0, len );
			return;
		}

		int[] u = Nat.copy( len, x );
		int[] a = new int[ len ];
		a[ 0 ] = 1;
		int ac = 0;

		if( (u[ 0 ] & 1) == 0 )
		{
			ac = inversionStep( p, u, len, a, ac );
		}
		if( Nat.isOne( len, u ) )
		{
			inversionResult( p, ac, a, z );
			return;
		}

		int[] v = Nat.copy( len, p );
		int[] b = new int[ len ];
		int bc = 0;

		int uvLen = len;

		for( ;; )
		{
			while( u[ uvLen - 1 ] == 0 && v[ uvLen - 1 ] == 0 )
			{
				--uvLen;
			}

			if( Nat.gte( uvLen, u, v ) )
			{
				Nat.subFrom( uvLen, v, u );
				ac += Nat.subFrom( len, b, a ) - bc;
				ac = inversionStep( p, u, uvLen, a, ac );
				if( Nat.isOne( uvLen, u ) )
				{
					inversionResult( p, ac, a, z );
					return;
				}
			}
			else
			{
				Nat.subFrom( uvLen, u, v );
				bc += Nat.subFrom( len, a, b ) - ac;
				bc = inversionStep( p, v, uvLen, b, bc );
				if( Nat.isOne( uvLen, v ) )
				{
					inversionResult( p, bc, b, z );
					return;
				}
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static final long M32 = 0x55555555L;
	private static final long M64 = 0x5555555555555555L;

	public static int expand8to16( int x )
	{
		x &= 0xFF;
		x = (x | (x << 4)) & 0x0F0F;
		x = (x | (x << 2)) & 0x3333;
		x = (x | (x << 1)) & 0x5555;
		return x;
	}

	public static int expand16to32( int x )
	{
		x &= 0xFFFF;
		x = (x | (x << 8)) & 0x00FF00FF;
		x = (x | (x << 4)) & 0x0F0F0F0F;
		x = (x | (x << 2)) & 0x33333333;
		x = (x | (x << 1)) & 0x55555555;
		return x;
	}

	public static long expand32to64( int x )
	{
		// "shuffle" low half to even bits and high half to odd bits
		int t;
		t = (x ^ (x >>> 8)) & 0x0000FF00;
		x ^= (t ^ (t << 8));
		t = (x ^ (x >>> 4)) & 0x00F000F0;
		x ^= (t ^ (t << 4));
		t = (x ^ (x >>> 2)) & 0x0C0C0C0C;
		x ^= (t ^ (t << 2));
		t = (x ^ (x >>> 1)) & 0x22222222;
		x ^= (t ^ (t << 1));

		return ((x >>> 1) & M32) << 32 | (x & M32);
	}

	public static void expand64To128( long x, long[] z, int zOff )
	{
		// "shuffle" low half to even bits and high half to odd bits
		long t;
		t = (x ^ (x >>> 16)) & 0x00000000FFFF0000L;
		x ^= (t ^ (t << 16));
		t = (x ^ (x >>> 8)) & 0x0000FF000000FF00L;
		x ^= (t ^ (t << 8));
		t = (x ^ (x >>> 4)) & 0x00F000F000F000F0L;
		x ^= (t ^ (t << 4));
		t = (x ^ (x >>> 2)) & 0x0C0C0C0C0C0C0C0CL;
		x ^= (t ^ (t << 2));
		t = (x ^ (x >>> 1)) & 0x2222222222222222L;
		x ^= (t ^ (t << 1));

		z[ zOff ] = (x) & M64;
		z[ zOff + 1 ] = (x >>> 1) & M64;
	}

	public static long unshuffle( long x )
	{
		// "unshuffle" even bits to low half and odd bits to high half
		long t;
		t = (x ^ (x >>> 1)) & 0x2222222222222222L;
		x ^= (t ^ (t << 1));
		t = (x ^ (x >>> 2)) & 0x0C0C0C0C0C0C0C0CL;
		x ^= (t ^ (t << 2));
		t = (x ^ (x >>> 4)) & 0x00F000F000F000F0L;
		x ^= (t ^ (t << 4));
		t = (x ^ (x >>> 8)) & 0x0000FF000000FF00L;
		x ^= (t ^ (t << 8));
		t = (x ^ (x >>> 16)) & 0x00000000FFFF0000L;
		x ^= (t ^ (t << 16));
		return x;
	}
}
