package org.denom.crypt.blockcipher.gost;

import org.denom.crypt.hash.GOST_SBox;
import org.denom.crypt.blockcipher.*;

import static org.denom.Ex.MUST;

/**
 * implementation of GOST 28147-89
 */
public class GOST28147 implements BlockCipher
{
	protected static final int BLOCK_SIZE = 8;
	private int[] workingKey = null;
	private boolean forEncryption;

	private byte[] S = new byte[ 128 ];

	// -----------------------------------------------------------------------------------------------------------------
	public GOST28147()
	{
		this( GOST_SBox.D_Test );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public GOST28147( byte[] sBox )
	{
		MUST( sBox.length == S.length );
		System.arraycopy( sBox, 0, S, 0, sBox.length );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void init( boolean forEncryption, CipherParameters params )
	{
		MUST( params instanceof KeyParameter );
		workingKey = generateWorkingKey( forEncryption, ((KeyParameter)params).getKey() );
	}

	public String getAlgorithmName()
	{
		return "GOST28147";
	}

	// -----------------------------------------------------------------------------------------------------------------
	public int getBlockSize()
	{
		return BLOCK_SIZE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public int processBlock( byte[] in, int inOff, byte[] out, int outOff )
	{
		MUST( workingKey != null );
		MUST( (inOff + BLOCK_SIZE) <= in.length );
		MUST( (outOff + BLOCK_SIZE) <= out.length );
		GOST28147Func( in, inOff, out, outOff );
		return BLOCK_SIZE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void reset() {}

	// -----------------------------------------------------------------------------------------------------------------
	private int[] generateWorkingKey( boolean forEncryption, byte[] userKey )
	{
		this.forEncryption = forEncryption;
		MUST( userKey.length == 32 );

		int key[] = new int[ 8 ];
		for( int i = 0; i != 8; i++ )
		{
			key[ i ] = bytesToint( userKey, i * 4 );
		}

		return key;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private int GOST28147_mainStep( int n1, int key )
	{
		int cm = (key + n1); // CM1

		// S-box replacing

		int om = S[ 0 + ((cm >> (0 * 4)) & 0xF) ] << (0 * 4);
		om += S[ 16 + ((cm >> (1 * 4)) & 0xF) ] << (1 * 4);
		om += S[ 32 + ((cm >> (2 * 4)) & 0xF) ] << (2 * 4);
		om += S[ 48 + ((cm >> (3 * 4)) & 0xF) ] << (3 * 4);
		om += S[ 64 + ((cm >> (4 * 4)) & 0xF) ] << (4 * 4);
		om += S[ 80 + ((cm >> (5 * 4)) & 0xF) ] << (5 * 4);
		om += S[ 96 + ((cm >> (6 * 4)) & 0xF) ] << (6 * 4);
		om += S[ 112 + ((cm >> (7 * 4)) & 0xF) ] << (7 * 4);

		return Integer.rotateLeft( om, 11 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void GOST28147Func( byte[] in, int inOff, byte[] out, int outOff )
	{
		int N1, N2, tmp; //tmp -> for saving N1
		N1 = bytesToint( in, inOff );
		N2 = bytesToint( in, inOff + 4 );

		if( this.forEncryption )
		{
			for( int k = 0; k < 3; k++ ) // 1-24 steps
			{
				for( int j = 0; j < 8; j++ )
				{
					tmp = N1;
					N1 = N2 ^ GOST28147_mainStep( N1, workingKey[ j ] ); // CM2
					N2 = tmp;
				}
			}
			for( int j = 7; j > 0; j-- ) // 25-31 steps
			{
				tmp = N1;
				N1 = N2 ^ GOST28147_mainStep( N1, workingKey[ j ] ); // CM2
				N2 = tmp;
			}
		}
		else //decrypt
		{
			for( int j = 0; j < 8; j++ ) // 1-8 steps
			{
				tmp = N1;
				N1 = N2 ^ GOST28147_mainStep( N1, workingKey[ j ] ); // CM2
				N2 = tmp;
			}
			for( int k = 0; k < 3; k++ ) //9-31 steps
			{
				for( int j = 7; j >= 0; j-- )
				{
					if( (k == 2) && (j == 0) )
					{
						break; // break 32 step
					}
					tmp = N1;
					N1 = N2 ^ GOST28147_mainStep( N1, workingKey[ j ] ); // CM2
					N2 = tmp;
				}
			}
		}

		N2 = N2 ^ GOST28147_mainStep( N1, workingKey[ 0 ] ); // 32 step (N1=N1)

		intTobytes( N1, out, outOff );
		intTobytes( N2, out, outOff + 4 );
	}

	private int bytesToint( byte[] in, int inOff )
	{
		return ((in[ inOff + 3 ] << 24) & 0xff000000) + ((in[ inOff + 2 ] << 16) & 0xff0000) + ((in[ inOff + 1 ] << 8) & 0xff00) + (in[ inOff ] & 0xff);
	}

	//int to array of bytes
	private void intTobytes( int num, byte[] out, int outOff )
	{
		out[ outOff + 3 ] = (byte)(num >>> 24);
		out[ outOff + 2 ] = (byte)(num >>> 16);
		out[ outOff + 1 ] = (byte)(num >>> 8);
		out[ outOff ] = (byte)num;
	}

}
