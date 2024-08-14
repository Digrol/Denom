// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import java.util.Arrays;
import org.denom.Binary;

import static org.denom.Ex.THROW;

/**
 * Cryptographic hash function GOST R 34.11-94.
 * Very slow.
 */
public class GOST3411_94 extends IHash
{
	public static final int HASH_SIZE = 32;
	private static final int BLOCK_SIZE = 32;

	private byte[] H = new byte[ BLOCK_SIZE ];
	private byte[] M = new byte[ BLOCK_SIZE ];
	private byte[] Sum = new byte[ BLOCK_SIZE ];
	private byte[][] C = new byte[ 4 ][ BLOCK_SIZE ];
	private Binary L = new Binary( BLOCK_SIZE );

	// -----------------------------------------------------------------------------------------------------------------
	public GOST3411_94()
	{
		super( BLOCK_SIZE );
		reset();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public GOST3411_94 clone()
	{
		THROW( "GOST3411_94 clone Not implemented" );
		return null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public GOST3411_94 cloneState()
	{
		THROW( "GOST3411_94 cloneState Not implemented" );
		return null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String name()
	{
		return "GOST3411";
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int size()
	{
		return HASH_SIZE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void reset()
	{
		super.reset();
		Arrays.fill( Sum, (byte)0 );
		Arrays.fill( H, (byte)0 );
		Arrays.fill( C[ 1 ], (byte)0 );
		Arrays.fill( C[ 3 ], (byte)0 );
		System.arraycopy( C2, 0, C[ 2 ], 0, C2.length );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary getHash()
	{
		finish();
		Binary hash = new Binary( H );
		reset();
		return hash;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void finish()
	{
		if( tail.size() != 0 )
		{
			tail.resize( BLOCK_SIZE );
			processBlock( tail, 0 );
		}

		L.setLongLE( 0, processedBytes << 3 );
		processBlockMain( L.getDataRef(), 0 );
		processBlockMain( Sum, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void processBlock( Binary data, int offset )
	{
		sumByteArray( data.getDataRef(), offset );
		processBlockMain( data.getDataRef(), offset );
	}

	// -----------------------------------------------------------------------------------------------------------------
	// A(x) = (x0 ^ x1) || x3 || x2 || x1
	byte[] a = new byte[ 8 ];

	private byte[] A( byte[] in )
	{
		for( int j = 0; j < 8; j++ )
		{
			a[ j ] = (byte)(in[ j ] ^ in[ j + 8 ]);
		}

		System.arraycopy( in, 8, in, 0, 24 );
		System.arraycopy( a, 0, in, 24, 8 );

		return in;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void Encrypt( byte[] s, int sOff, byte[] in, int inOff )
	{
		for( int i = 0; i < 8; i++ )
		{
			workingKey[ i ] = (W[ i ] & 0xFF) | ((W[ 8 + i ] & 0xFF) << 8) | ((W[ 16 + i ]  & 0xFF) << 16) | (W[ 24 + i ] << 24);
		}
		GOST28147Func( in, inOff, s, sOff );
	}

	private byte[] S = new byte[ BLOCK_SIZE ];
	private byte[] U = new byte[ BLOCK_SIZE ];
	private byte[] V = new byte[ BLOCK_SIZE ];
	private byte[] W = new byte[ BLOCK_SIZE ];

	private short[] wS = new short[ 16 ];
	private short[] w_S = new short[ 16 ];

	// -----------------------------------------------------------------------------------------------------------------
	private void fw()
	{
		for( int i = 0; i < S.length / 2; i++ )
		{
			wS[ i ] = (short)((S[ i * 2 + 1 ] << 8) | (S[ i * 2 ] & 0xFF));
		}

		w_S[ 15 ] = (short)(wS[ 0 ] ^ wS[ 1 ] ^ wS[ 2 ] ^ wS[ 3 ] ^ wS[ 12 ] ^ wS[ 15 ]);
		System.arraycopy( wS, 1, w_S, 0, 15 );

		for( int i = 0; i < S.length / 2; i++ )
		{
			S[ i * 2 + 1 ] = (byte)(w_S[ i ] >> 8);
			S[ i * 2 ] = (byte)w_S[ i ];
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processBlockMain( byte[] in, int inOff )
	{
		System.arraycopy( in, inOff, M, 0, BLOCK_SIZE );

		System.arraycopy( H, 0, U, 0, 32 );
		System.arraycopy( M, 0, V, 0, 32 );
		for( int j = 0; j < 32; j++ )
		{
			W[ j ] = (byte)(U[ j ] ^ V[ j ]);
		}

		Encrypt( S, 0, H, 0 );

		for( int i = 1; i < 4; i++ )
		{
			byte[] tmpA = A( U );
			for( int j = 0; j < 32; j++ )
			{
				U[ j ] = (byte)(tmpA[ j ] ^ C[ i ][ j ]);
			}
			V = A( A( V ) );
			for( int j = 0; j < 32; j++ )
			{
				W[ j ] = (byte)(U[ j ] ^ V[ j ]);
			}

			Encrypt( S, i * 8, H, i * 8 ); // si = EKi [hi]
		}

		for( int n = 0; n < 12; n++ )
		{
			fw();
		}
		for( int i = 0; i < 32; i++ )
		{
			S[ i ] = (byte)(S[ i ] ^ M[ i ]);
		}

		fw();

		for( int i = 0; i < 32; i++ )
		{
			S[ i ] = (byte)(S[ i ] ^ H[ i ]);
		}
		for( int i = 0; i < 61; i++ )
		{
			fw();
		}
		System.arraycopy( S, 0, H, 0, H.length );
	}


	// -----------------------------------------------------------------------------------------------------------------
	private static final byte[] C2 = {
			0x00, (byte)0xFF, 0x00, (byte)0xFF, 0x00, (byte)0xFF, 0x00, (byte)0xFF,
			(byte)0xFF, 0x00, (byte)0xFF, 0x00, (byte)0xFF, 0x00, (byte)0xFF, 0x00,
			0x00, (byte)0xFF, (byte)0xFF, 0x00, (byte)0xFF, 0x00, 0x00, (byte)0xFF,
			(byte)0xFF, 0x00, 0x00, 0x00, (byte)0xFF, (byte)0xFF, 0x00, (byte)0xFF };

	// -----------------------------------------------------------------------------------------------------------------
	private void sumByteArray( byte[] in, int offset )
	{
		for( int i = 0, carry = 0; i != Sum.length; i++ )
		{
			int sum = (Sum[ i ] & 0xff) + (in[ offset + i ] & 0xff) + carry;
			Sum[ i ] = (byte)sum;
			carry = sum >>> 8;
		}
	}

	private int[] workingKey = new int[ 8 ];
	private byte[] SBox = GOST_SBox.D_A;

	// -----------------------------------------------------------------------------------------------------------------
	private int GOST28147Step( int n1, int key )
	{
		int cm = (key + n1); // CM1

		int om = SBox[ 0 + ((cm >> (0 * 4)) & 0xF) ] << (0 * 4);
		om += SBox[ 16 + ((cm >> (1 * 4)) & 0xF) ] << (1 * 4);
		om += SBox[ 32 + ((cm >> (2 * 4)) & 0xF) ] << (2 * 4);
		om += SBox[ 48 + ((cm >> (3 * 4)) & 0xF) ] << (3 * 4);
		om += SBox[ 64 + ((cm >> (4 * 4)) & 0xF) ] << (4 * 4);
		om += SBox[ 80 + ((cm >> (5 * 4)) & 0xF) ] << (5 * 4);
		om += SBox[ 96 + ((cm >> (6 * 4)) & 0xF) ] << (6 * 4);
		om += SBox[ 112 + ((cm >> (7 * 4)) & 0xF) ] << (7 * 4);

		return Integer.rotateLeft( om, 11 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void GOST28147Func( byte[] in, int inOff, byte[] out, int outOff )
	{
		int N1 = bytesToInt( in, inOff );
		int N2 = bytesToInt( in, inOff + 4 );

		for( int k = 0; k < 3; k++ ) // 1-24 steps
		{
			for( int j = 0; j < 8; j++ )
			{
				int t = N1;
				N1 = N2 ^ GOST28147Step( N1, workingKey[ j ] );
				N2 = t;
			}
		}

		for( int j = 7; j > 0; j-- ) // 25-31 steps
		{
			int t = N1;
			N1 = N2 ^ GOST28147Step( N1, workingKey[ j ] );
			N2 = t;
		}

		N2 = N2 ^ GOST28147Step( N1, workingKey[ 0 ] );

		intToBytes( N1, out, outOff );
		intToBytes( N2, out, outOff + 4 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private int bytesToInt( byte[] in, int inOff )
	{
		return ((in[ inOff + 3 ] << 24) & 0xff000000)
			+ ((in[ inOff + 2 ] << 16) & 0xff0000)
			+ ((in[ inOff + 1 ] << 8) & 0xff00)
			+ (in[ inOff ] & 0xff);
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void intToBytes( int num, byte[] out, int outOff )
	{
		out[ outOff + 3 ] = (byte)(num >>> 24);
		out[ outOff + 2 ] = (byte)(num >>> 16);
		out[ outOff + 1 ] = (byte)(num >>> 8);
		out[ outOff ] = (byte)num;
	}
}
