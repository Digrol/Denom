package org.denom.crypt.ec.rfc7748;

import java.util.Arrays;
import org.denom.Binary;
import org.denom.crypt.hash.SHA512;
import org.denom.crypt.ec.Nat;

import static org.denom.Binary.Bin;

/**
 * RFC 8032
 */
public abstract class Ed25519
{
	private static final long M28L = 0x0FFFFFFFL;
	private static final long M32L = 0xFFFFFFFFL;

	private static final int POINT_BYTES = 32;
	private static final int SCALAR_INTS = 8;
	private static final int SCALAR_BYTES = SCALAR_INTS * 4;

	public static final int PUBLIC_KEY_SIZE = POINT_BYTES;
	public static final int SECRET_KEY_SIZE = 32;
	public static final int SIGNATURE_SIZE = POINT_BYTES + SCALAR_BYTES;

	private static final int[] P = new int[] { 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF };
	private static final int[] L = new int[] { 0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0x00000000, 0x00000000, 0x00000000, 0x10000000 };

	private static final int L0 = 0xFCF5D3ED; // L0:26/--
	private static final int L1 = 0x012631A6; // L1:24/22
	private static final int L2 = 0x079CD658; // L2:27/--
	private static final int L3 = 0xFF9DEA2F; // L3:23/--
	private static final int L4 = 0x000014DF; // L4:12/11

	private static final int[] B_x = new int[] { 0x0325D51A, 0x018B5823, 0x007B2C95, 0x0304A92D, 0x00D2598E, 0x01D6DC5C, 0x01388C7F, 0x013FEC0A, 0x029E6B72, 0x0042D26D };
	private static final int[] B_y = new int[] { 0x02666658, 0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, 0x02666666, 0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, };
	private static final int[] C_d = new int[] { 0x035978A3, 0x02D37284, 0x018AB75E, 0x026A0A0E, 0x0000E014, 0x0379E898, 0x01D01E5D, 0x01E738CC, 0x03715B7F, 0x00A406D9 };
	private static final int[] C_d2 = new int[] { 0x02B2F159, 0x01A6E509, 0x01156EBD, 0x00D4141D, 0x0001C029, 0x02F3D130, 0x03A03CBB, 0x01CE7198, 0x02E2B6FF, 0x00480DB3 };
	private static final int[] C_d4 = new int[] { 0x0165E2B2, 0x034DCA13, 0x002ADD7A, 0x01A8283B, 0x00038052, 0x01E7A260, 0x03407977, 0x019CE331, 0x01C56DFF, 0x00901B67 };

	private static final int WNAF_WIDTH_BASE = 7;

	private static final int PRECOMP_BLOCKS = 8;
	private static final int PRECOMP_TEETH = 4;
	private static final int PRECOMP_SPACING = 8;
	private static final int PRECOMP_POINTS = 1 << (PRECOMP_TEETH - 1);
	private static final int PRECOMP_MASK = PRECOMP_POINTS - 1;

	private static PointExt[] precompBaseTable = null;
	private static int[] precompBase = null;

	private static class PointExt
	{
		int[] x = X25519.create();
		int[] y = X25519.create();
		int[] z = X25519.create();
		int[] t = X25519.create();
	}

	private static class PointPrecomp
	{
		int[] ypx_h = X25519.create();
		int[] ymx_h = X25519.create();
		int[] xyd = X25519.create();
	}

	private static byte[] calculateS( byte[] r, byte[] k, byte[] s )
	{
		int[] t = new int[ SCALAR_INTS * 2 ];
		decodeScalar( r, 0, t );
		int[] u = new int[ SCALAR_INTS ];
		decodeScalar( k, 0, u );
		int[] v = new int[ SCALAR_INTS ];
		decodeScalar( s, 0, v );

		Nat.mulAddTo( u.length, u, v, t );

		byte[] result = new byte[ SCALAR_BYTES * 2 ];
		for( int i = 0; i < t.length; ++i )
		{
			encode32( t[ i ], result, i * 4 );
		}
		return reduceScalar( result );
	}

	private static boolean checkPointVar( byte[] p )
	{
		int[] t = new int[ SCALAR_INTS ];
		decode32( p, 0, t, 0, 8 );
		t[ 7 ] &= 0x7FFFFFFF;
		return !Nat.gte( SCALAR_INTS, t, P );
	}

	private static boolean checkScalarVar( byte[] s )
	{
		int[] n = new int[ SCALAR_INTS ];
		decodeScalar( s, 0, n );
		return !Nat.gte( SCALAR_INTS, n, L );
	}

	private static int decode24( byte[] bs, int off )
	{
		int n = bs[ off ] & 0xFF;
		n |= (bs[ ++off ] & 0xFF) << 8;
		n |= (bs[ ++off ] & 0xFF) << 16;
		return n;
	}

	private static int decode32( byte[] bs, int off )
	{
		int n = bs[ off ] & 0xFF;
		n |= (bs[ ++off ] & 0xFF) << 8;
		n |= (bs[ ++off ] & 0xFF) << 16;
		n |= bs[ ++off ] << 24;
		return n;
	}

	private static void decode32( byte[] bs, int bsOff, int[] n, int nOff, int nLen )
	{
		for( int i = 0; i < nLen; ++i )
		{
			n[ nOff + i ] = decode32( bs, bsOff + i * 4 );
		}
	}

	private static boolean decodePointVar( byte[] p, int pOff, boolean negate, PointExt r )
	{
		byte[] py = Arrays.copyOfRange( p, pOff, pOff + POINT_BYTES );
		if( !checkPointVar( py ) )
		{
			return false;
		}

		int x_0 = (py[ POINT_BYTES - 1 ] & 0x80) >>> 7;
		py[ POINT_BYTES - 1 ] &= 0x7F;

		X25519.decode( py, 0, r.y );

		int[] u = X25519.create();
		int[] v = X25519.create();

		X25519.sqr( r.y, u );
		X25519.mul( C_d, u, v );
		X25519.subOne( u );
		X25519.addOne( v );

		if( !X25519.sqrtRatioVar( u, v, r.x ) )
		{
			return false;
		}

		X25519.normalize( r.x );
		if( x_0 == 1 && X25519.isZeroVar( r.x ) )
		{
			return false;
		}

		if( negate ^ (x_0 != (r.x[ 0 ] & 1)) )
		{
			X25519.negate( r.x, r.x );
		}

		pointExtendXY( r );
		return true;
	}

	private static void decodeScalar( byte[] k, int kOff, int[] n )
	{
		decode32( k, kOff, n, 0, SCALAR_INTS );
	}

	private static void encode24( int n, byte[] bs, int off )
	{
		bs[ off ] = (byte)(n);
		bs[ ++off ] = (byte)(n >>> 8);
		bs[ ++off ] = (byte)(n >>> 16);
	}

	private static void encode32( int n, byte[] bs, int off )
	{
		bs[ off ] = (byte)(n);
		bs[ ++off ] = (byte)(n >>> 8);
		bs[ ++off ] = (byte)(n >>> 16);
		bs[ ++off ] = (byte)(n >>> 24);
	}

	private static void encode56( long n, byte[] bs, int off )
	{
		encode32( (int)n, bs, off );
		encode24( (int)(n >>> 32), bs, off + 4 );
	}

	private static void encodePoint( PointExt p, byte[] r, int rOff )
	{
		int[] x = X25519.create();
		int[] y = X25519.create();

		X25519.inv( p.z, y );
		X25519.mul( p.x, y, x );
		X25519.mul( p.y, y, y );
		X25519.normalize( x );
		X25519.normalize( y );

		X25519.encode( y, r, rOff );
		r[ rOff + POINT_BYTES - 1 ] |= ((x[ 0 ] & 1) << 7);
	}

	public static void generatePublicKey( byte[] sk, int skOff, byte[] pk, int pkOff )
	{
		byte[] hash = new SHA512().calc( new Binary( sk, skOff, SECRET_KEY_SIZE ) ).getBytes();
		byte[] s = new byte[ SCALAR_BYTES ];
		pruneScalar( hash, 0, s );
		scalarMultBaseEncoded( s, pk, pkOff );
	}

	private static byte[] getWNAF( int[] n, int width )
	{

		int[] t = new int[ SCALAR_INTS * 2 ];
		{
			int tPos = t.length, c = 0;
			int i = SCALAR_INTS;
			while( --i >= 0 )
			{
				int next = n[ i ];
				t[ --tPos ] = (next >>> 16) | (c << 16);
				t[ --tPos ] = c = next;
			}
		}

		byte[] ws = new byte[ 256 ];

		final int pow2 = 1 << width;
		final int mask = pow2 - 1;
		final int sign = pow2 >>> 1;

		int j = 0, carry = 0;
		for( int i = 0; i < t.length; ++i, j -= 16 )
		{
			int word = t[ i ];
			while( j < 16 )
			{
				int word16 = word >>> j;
				int bit = word16 & 1;

				if( bit == carry )
				{
					++j;
					continue;
				}

				int digit = (word16 & mask) + carry;
				carry = digit & sign;
				digit -= (carry << 1);
				carry >>>= (width - 1);

				ws[ (i << 4) + j ] = (byte)digit;

				j += width;
			}
		}

		return ws;
	}

	private static void implSign( byte[] h, byte[] s, byte[] pk, int pkOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff )
	{
		SHA512 alg = new SHA512();

		Binary data = new Binary();
		data.add( h, SCALAR_BYTES, SCALAR_BYTES );
		data.add( m, mOff, mLen );
		byte[] r = reduceScalar( alg.calc( data ).getBytes() );
		byte[] R = new byte[ POINT_BYTES ];
		scalarMultBaseEncoded( r, R, 0 );

		data = new Binary();
		data.add( R, 0, POINT_BYTES );
		data.add( pk, pkOff, POINT_BYTES );
		data.add( m, mOff, mLen );
		byte[] k = reduceScalar( alg.calc( data ).getBytes() );
		byte[] S = calculateS( r, k, s );

		System.arraycopy( R, 0, sig, sigOff, POINT_BYTES );
		System.arraycopy( S, 0, sig, sigOff + POINT_BYTES, SCALAR_BYTES );
	}

	private static void pointAddVar( boolean negate, PointExt p, PointExt r )
	{
		int[] A = X25519.create();
		int[] B = X25519.create();
		int[] C = X25519.create();
		int[] D = X25519.create();
		int[] E = X25519.create();
		int[] F = X25519.create();
		int[] G = X25519.create();
		int[] H = X25519.create();

		int[] c, d, f, g;
		if( negate )
		{
			c = D;
			d = C;
			f = G;
			g = F;
		}
		else
		{
			c = C;
			d = D;
			f = F;
			g = G;
		}

		X25519.apm( r.y, r.x, B, A );
		X25519.apm( p.y, p.x, d, c );
		X25519.mul( A, C, A );
		X25519.mul( B, D, B );
		X25519.mul( r.t, p.t, C );
		X25519.mul( C, C_d2, C );
		X25519.mul( r.z, p.z, D );
		X25519.add( D, D, D );
		X25519.apm( B, A, H, E );
		X25519.apm( D, C, g, f );
		X25519.carry( g );
		X25519.mul( E, F, r.x );
		X25519.mul( G, H, r.y );
		X25519.mul( F, G, r.z );
		X25519.mul( E, H, r.t );
	}

	private static void pointAddPrecomp( PointPrecomp p, PointExt r )
	{
		int[] A = X25519.create();
		int[] B = X25519.create();
		int[] C = X25519.create();
		int[] E = X25519.create();
		int[] F = X25519.create();
		int[] G = X25519.create();
		int[] H = X25519.create();

		X25519.apm( r.y, r.x, B, A );
		X25519.mul( A, p.ymx_h, A );
		X25519.mul( B, p.ypx_h, B );
		X25519.mul( r.t, p.xyd, C );
		X25519.apm( B, A, H, E );
		X25519.apm( r.z, C, G, F );
		X25519.carry( G );
		X25519.mul( E, F, r.x );
		X25519.mul( G, H, r.y );
		X25519.mul( F, G, r.z );
		X25519.mul( E, H, r.t );
	}

	private static PointExt pointCopy( PointExt p )
	{
		PointExt r = new PointExt();
		X25519.copy( p.x, 0, r.x, 0 );
		X25519.copy( p.y, 0, r.y, 0 );
		X25519.copy( p.z, 0, r.z, 0 );
		X25519.copy( p.t, 0, r.t, 0 );
		return r;
	}

	private static void pointDouble( PointExt r )
	{
		int[] A = X25519.create();
		int[] B = X25519.create();
		int[] C = X25519.create();
		int[] E = X25519.create();
		int[] F = X25519.create();
		int[] G = X25519.create();
		int[] H = X25519.create();

		X25519.sqr( r.x, A );
		X25519.sqr( r.y, B );
		X25519.sqr( r.z, C );
		X25519.add( C, C, C );
		X25519.apm( A, B, H, G );
		X25519.add( r.x, r.y, E );
		X25519.sqr( E, E );
		X25519.sub( H, E, E );
		X25519.add( C, G, F );
		X25519.carry( F );
		X25519.mul( E, F, r.x );
		X25519.mul( G, H, r.y );
		X25519.mul( F, G, r.z );
		X25519.mul( E, H, r.t );
	}

	private static void pointExtendXY( PointExt p )
	{
		X25519.one( p.z );
		X25519.mul( p.x, p.y, p.t );
	}

	private static void pointLookup( int block, int index, PointPrecomp p )
	{
		int off = block * PRECOMP_POINTS * 3 * X25519.SIZE;

		for( int i = 0; i < PRECOMP_POINTS; ++i )
		{
			int mask = ((i ^ index) - 1) >> 31;
			Nat.cmov( X25519.SIZE, mask, precompBase, off, p.ypx_h, 0 );
			off += X25519.SIZE;
			Nat.cmov( X25519.SIZE, mask, precompBase, off, p.ymx_h, 0 );
			off += X25519.SIZE;
			Nat.cmov( X25519.SIZE, mask, precompBase, off, p.xyd, 0 );
			off += X25519.SIZE;
		}
	}

	private static PointExt[] pointPrecompVar( PointExt p, int count )
	{
		PointExt d = pointCopy( p );
		pointDouble( d );

		PointExt[] table = new PointExt[ count ];
		table[ 0 ] = pointCopy( p );
		for( int i = 1; i < count; ++i )
		{
			table[ i ] = pointCopy( table[ i - 1 ] );
			pointAddVar( false, d, table[ i ] );
		}
		return table;
	}

	private static void pointSetNeutral( PointExt p )
	{
		X25519.zero( p.x );
		X25519.one( p.y );
		X25519.one( p.z );
		X25519.zero( p.t );
	}

	public synchronized static void precompute()
	{
		if( precompBase != null )
		{
			return;
		}

		PointExt p = new PointExt();
		X25519.copy( B_x, 0, p.x, 0 );
		X25519.copy( B_y, 0, p.y, 0 );
		pointExtendXY( p );

		precompBaseTable = pointPrecompVar( p, 1 << (WNAF_WIDTH_BASE - 2) );

		precompBase = new int[ PRECOMP_BLOCKS * PRECOMP_POINTS * 3 * X25519.SIZE ];

		int off = 0;
		for( int b = 0; b < PRECOMP_BLOCKS; ++b )
		{
			PointExt[] ds = new PointExt[ PRECOMP_TEETH ];

			PointExt sum = new PointExt();
			pointSetNeutral( sum );

			for( int t = 0; t < PRECOMP_TEETH; ++t )
			{
				pointAddVar( true, p, sum );
				pointDouble( p );

				ds[ t ] = pointCopy( p );

				for( int s = 1; s < PRECOMP_SPACING; ++s )
				{
					pointDouble( p );
				}
			}

			PointExt[] points = new PointExt[ PRECOMP_POINTS ];
			int k = 0;
			points[ k++ ] = sum;

			for( int t = 0; t < (PRECOMP_TEETH - 1); ++t )
			{
				int size = 1 << t;
				for( int j = 0; j < size; ++j )
				{
					points[ k ] = pointCopy( points[ k - size ] );
					pointAddVar( false, ds[ t ], points[ k++ ] );
				}
			}

			for( int i = 0; i < PRECOMP_POINTS; ++i )
			{
				PointExt q = points[ i ];

				int[] x = X25519.create();
				int[] y = X25519.create();

				X25519.add( q.z, q.z, x );

				X25519.inv( x, y );
				X25519.mul( q.x, y, x );
				X25519.mul( q.y, y, y );

				PointPrecomp r = new PointPrecomp();
				X25519.apm( y, x, r.ypx_h, r.ymx_h );
				X25519.mul( x, y, r.xyd );
				X25519.mul( r.xyd, C_d4, r.xyd );

				X25519.normalize( r.ypx_h );
				X25519.normalize( r.ymx_h );

				X25519.copy( r.ypx_h, 0, precompBase, off );
				off += X25519.SIZE;
				X25519.copy( r.ymx_h, 0, precompBase, off );
				off += X25519.SIZE;
				X25519.copy( r.xyd, 0, precompBase, off );
				off += X25519.SIZE;
			}
		}
	}

	private static void pruneScalar( byte[] n, int nOff, byte[] r )
	{
		System.arraycopy( n, nOff, r, 0, SCALAR_BYTES );

		r[ 0 ] &= 0xF8;
		r[ SCALAR_BYTES - 1 ] &= 0x7F;
		r[ SCALAR_BYTES - 1 ] |= 0x40;
	}

	private static byte[] reduceScalar( byte[] n )
	{
		long x00 = decode32( n, 0 ) & M32L; // x00:32/--
		long x01 = (decode24( n, 4 ) << 4) & M32L; // x01:28/--
		long x02 = decode32( n, 7 ) & M32L; // x02:32/--
		long x03 = (decode24( n, 11 ) << 4) & M32L; // x03:28/--
		long x04 = decode32( n, 14 ) & M32L; // x04:32/--
		long x05 = (decode24( n, 18 ) << 4) & M32L; // x05:28/--
		long x06 = decode32( n, 21 ) & M32L; // x06:32/--
		long x07 = (decode24( n, 25 ) << 4) & M32L; // x07:28/--
		long x08 = decode32( n, 28 ) & M32L; // x08:32/--
		long x09 = (decode24( n, 32 ) << 4) & M32L; // x09:28/--
		long x10 = decode32( n, 35 ) & M32L; // x10:32/--
		long x11 = (decode24( n, 39 ) << 4) & M32L; // x11:28/--
		long x12 = decode32( n, 42 ) & M32L; // x12:32/--
		long x13 = (decode24( n, 46 ) << 4) & M32L; // x13:28/--
		long x14 = decode32( n, 49 ) & M32L; // x14:32/--
		long x15 = (decode24( n, 53 ) << 4) & M32L; // x15:28/--
		long x16 = decode32( n, 56 ) & M32L; // x16:32/--
		long x17 = (decode24( n, 60 ) << 4) & M32L; // x17:28/--
		long x18 = n[ 63 ] & 0xFFL; // x18:08/--
		long t;

		x09 -= x18 * L0; // x09:34/28
		x10 -= x18 * L1; // x10:33/30
		x11 -= x18 * L2; // x11:35/28
		x12 -= x18 * L3; // x12:32/31
		x13 -= x18 * L4; // x13:28/21

		x17 += (x16 >> 28);
		x16 &= M28L; // x17:28/--, x16:28/--
		x08 -= x17 * L0; // x08:54/32
		x09 -= x17 * L1; // x09:52/51
		x10 -= x17 * L2; // x10:55/34
		x11 -= x17 * L3; // x11:51/36
		x12 -= x17 * L4; // x12:41/--

		x07 -= x16 * L0; // x07:54/28
		x08 -= x16 * L1; // x08:54/53
		x09 -= x16 * L2; // x09:55/53
		x10 -= x16 * L3; // x10:55/52
		x11 -= x16 * L4; // x11:51/41

		x15 += (x14 >> 28);
		x14 &= M28L; // x15:28/--, x14:28/--
		x06 -= x15 * L0; // x06:54/32
		x07 -= x15 * L1; // x07:54/53
		x08 -= x15 * L2; // x08:56/--
		x09 -= x15 * L3; // x09:55/54
		x10 -= x15 * L4; // x10:55/53

		x05 -= x14 * L0; // x05:54/28
		x06 -= x14 * L1; // x06:54/53
		x07 -= x14 * L2; // x07:56/--
		x08 -= x14 * L3; // x08:56/51
		x09 -= x14 * L4; // x09:56/--

		x13 += (x12 >> 28);
		x12 &= M28L; // x13:28/22, x12:28/--
		x04 -= x13 * L0; // x04:54/49
		x05 -= x13 * L1; // x05:54/53
		x06 -= x13 * L2; // x06:56/--
		x07 -= x13 * L3; // x07:56/52
		x08 -= x13 * L4; // x08:56/52

		x12 += (x11 >> 28);
		x11 &= M28L; // x12:28/24, x11:28/--
		x03 -= x12 * L0; // x03:54/49
		x04 -= x12 * L1; // x04:54/51
		x05 -= x12 * L2; // x05:56/--
		x06 -= x12 * L3; // x06:56/52
		x07 -= x12 * L4; // x07:56/53

		x11 += (x10 >> 28);
		x10 &= M28L; // x11:29/--, x10:28/--
		x02 -= x11 * L0; // x02:55/32
		x03 -= x11 * L1; // x03:55/--
		x04 -= x11 * L2; // x04:56/55
		x05 -= x11 * L3; // x05:56/52
		x06 -= x11 * L4; // x06:56/53

		x10 += (x09 >> 28);
		x09 &= M28L; // x10:29/--, x09:28/--
		x01 -= x10 * L0; // x01:55/28
		x02 -= x10 * L1; // x02:55/54
		x03 -= x10 * L2; // x03:56/55
		x04 -= x10 * L3; // x04:57/--
		x05 -= x10 * L4; // x05:56/53

		x08 += (x07 >> 28);
		x07 &= M28L; // x08:56/53, x07:28/--
		x09 += (x08 >> 28);
		x08 &= M28L; // x09:29/25, x08:28/--

		t = x08 >>> 27;
		x09 += t; // x09:29/26

		x00 -= x09 * L0; // x00:55/53
		x01 -= x09 * L1; // x01:55/54
		x02 -= x09 * L2; // x02:57/--
		x03 -= x09 * L3; // x03:57/--
		x04 -= x09 * L4; // x04:57/42

		x01 += (x00 >> 28);
		x00 &= M28L;
		x02 += (x01 >> 28);
		x01 &= M28L;
		x03 += (x02 >> 28);
		x02 &= M28L;
		x04 += (x03 >> 28);
		x03 &= M28L;
		x05 += (x04 >> 28);
		x04 &= M28L;
		x06 += (x05 >> 28);
		x05 &= M28L;
		x07 += (x06 >> 28);
		x06 &= M28L;
		x08 += (x07 >> 28);
		x07 &= M28L;
		x09 = (x08 >> 28);
		x08 &= M28L;

		x09 -= t;

		x00 += x09 & L0;
		x01 += x09 & L1;
		x02 += x09 & L2;
		x03 += x09 & L3;
		x04 += x09 & L4;

		x01 += (x00 >> 28);
		x00 &= M28L;
		x02 += (x01 >> 28);
		x01 &= M28L;
		x03 += (x02 >> 28);
		x02 &= M28L;
		x04 += (x03 >> 28);
		x03 &= M28L;
		x05 += (x04 >> 28);
		x04 &= M28L;
		x06 += (x05 >> 28);
		x05 &= M28L;
		x07 += (x06 >> 28);
		x06 &= M28L;
		x08 += (x07 >> 28);
		x07 &= M28L;

		byte[] r = new byte[ SCALAR_BYTES ];
		encode56( x00 | (x01 << 28), r, 0 );
		encode56( x02 | (x03 << 28), r, 7 );
		encode56( x04 | (x05 << 28), r, 14 );
		encode56( x06 | (x07 << 28), r, 21 );
		encode32( (int)x08, r, 28 );
		return r;
	}


	private static int shuffle2( int x )
	{
		// "shuffle" (twice) low half to even bits and high half to odd bits
		int t;
		t = (x ^ (x >>> 7)) & 0x00AA00AA;
		x ^= (t ^ (t << 7));
		t = (x ^ (x >>> 14)) & 0x0000CCCC;
		x ^= (t ^ (t << 14));
		t = (x ^ (x >>> 4)) & 0x00F000F0;
		x ^= (t ^ (t << 4));
		t = (x ^ (x >>> 8)) & 0x0000FF00;
		x ^= (t ^ (t << 8));
		return x;
	}

	private static void scalarMultBase( byte[] k, PointExt r )
	{
		precompute();

		pointSetNeutral( r );

		int[] n = new int[ SCALAR_INTS ];
		decodeScalar( k, 0, n );

		// Recode the scalar into signed-digit form, then group comb bits in each block
		{
			Nat.cadd( SCALAR_INTS, ~n[ 0 ] & 1, n, L, n );
			Nat.shiftDownBit( SCALAR_INTS, n, 1 );

			for( int i = 0; i < SCALAR_INTS; ++i )
			{
				n[ i ] = shuffle2( n[ i ] );
			}
		}

		PointPrecomp p = new PointPrecomp();

		int cOff = (PRECOMP_SPACING - 1) * PRECOMP_TEETH;
		for( ;; )
		{
			for( int b = 0; b < PRECOMP_BLOCKS; ++b )
			{
				int w = n[ b ] >>> cOff;
				int sign = (w >>> (PRECOMP_TEETH - 1)) & 1;
				int abs = (w ^ -sign) & PRECOMP_MASK;

				pointLookup( b, abs, p );

				X25519.cswap( sign, p.ypx_h, p.ymx_h );
				X25519.cnegate( sign, p.xyd );

				pointAddPrecomp( p, r );
			}

			if( (cOff -= PRECOMP_TEETH) < 0 )
			{
				break;
			}

			pointDouble( r );
		}
	}

	private static void scalarMultBaseEncoded( byte[] k, byte[] r, int rOff )
	{
		PointExt p = new PointExt();
		scalarMultBase( k, p );
		encodePoint( p, r, rOff );
	}

	private static void scalarMultStraussVar( int[] nb, int[] np, PointExt p, PointExt r )
	{
		precompute();

		final int width = 5;

		byte[] ws_b = getWNAF( nb, WNAF_WIDTH_BASE );
		byte[] ws_p = getWNAF( np, width );

		PointExt[] tp = pointPrecompVar( p, 1 << (width - 2) );

		pointSetNeutral( r );

		int bit = 255;
		while( bit > 0 && (ws_b[ bit ] | ws_p[ bit ]) == 0 )
		{
			--bit;
		}

		for( ;; )
		{
			int wb = ws_b[ bit ];
			if( wb != 0 )
			{
				int sign = wb >> 31;
				int index = (wb ^ sign) >>> 1;

				pointAddVar( (sign != 0), precompBaseTable[ index ], r );
			}

			int wp = ws_p[ bit ];
			if( wp != 0 )
			{
				int sign = wp >> 31;
				int index = (wp ^ sign) >>> 1;

				pointAddVar( (sign != 0), tp[ index ], r );
			}

			if( --bit < 0 )
			{
				break;
			}

			pointDouble( r );
		}
	}

	public static void sign( byte[] sk, int skOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff )
	{
		byte[] hash = new SHA512().calc( new Binary( sk, skOff, SECRET_KEY_SIZE ) ).getBytes();
		byte[] s = new byte[ SCALAR_BYTES ];
		pruneScalar( hash, 0, s );

		byte[] pk = new byte[ POINT_BYTES ];
		scalarMultBaseEncoded( s, pk, 0 );

		implSign( hash, s, pk, 0, m, mOff, mLen, sig, sigOff );
	}

	public static void sign( byte[] sk, int skOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff )
	{
		byte[] hash = new SHA512().calc( new Binary( sk, skOff, SECRET_KEY_SIZE ) ).getBytes();
		byte[] s = new byte[ SCALAR_BYTES ];
		pruneScalar( hash, 0, s );

		implSign( hash, s, pk, pkOff, m, mOff, mLen, sig, sigOff );
	}

	public static boolean verify( byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen )
	{
		byte[] R = Arrays.copyOfRange( sig, sigOff, sigOff + POINT_BYTES );
		byte[] S = Arrays.copyOfRange( sig, sigOff + POINT_BYTES, sigOff + SIGNATURE_SIZE );

		if( !checkPointVar( R ) )
		{
			return false;
		}
		if( !checkScalarVar( S ) )
		{
			return false;
		}

		PointExt pA = new PointExt();
		if( !decodePointVar( pk, pkOff, true, pA ) )
		{
			return false;
		}

		Binary data = Bin().reserve( POINT_BYTES * 2 + mLen );
		data.add( R, 0, POINT_BYTES );
		data.add( pk, pkOff, POINT_BYTES );
		data.add( m, mOff, mLen );
		byte[] hash = new SHA512().calc( data ).getBytes();

		byte[] k = reduceScalar( hash );

		int[] nS = new int[ SCALAR_INTS ];
		decodeScalar( S, 0, nS );

		int[] nA = new int[ SCALAR_INTS ];
		decodeScalar( k, 0, nA );

		PointExt pR = new PointExt();
		scalarMultStraussVar( nS, nA, pA, pR );

		byte[] check = new byte[ POINT_BYTES ];
		encodePoint( pR, check, 0 );

		return Arrays.equals( check, R );
	}
}
