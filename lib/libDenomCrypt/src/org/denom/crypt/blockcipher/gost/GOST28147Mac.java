package org.denom.crypt.blockcipher.gost;

import java.util.Arrays;
import org.denom.crypt.hash.GOST_SBox;
import org.denom.Binary;

import static org.denom.Ex.MUST;

public class GOST28147Mac
{
	private int blockSize = 8;
	private int macSize = 4;
	private int bufOff;
	private byte[] buf;
	private byte[] mac;
	private boolean firstStep = true;
	private int[] workingKey = null;
	private byte[] macIV = null;

	private byte[] S = new byte[ 128 ];

	// -----------------------------------------------------------------------------------------------------------------
	public GOST28147Mac()
	{
		this( GOST_SBox.E_A );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public GOST28147Mac( byte[] sBox )
	{
		MUST( sBox.length == S.length );
		System.arraycopy( sBox, 0, this.S, 0, sBox.length );

		mac = new byte[ blockSize ];
		buf = new byte[ blockSize ];
		bufOff = 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public GOST28147Mac setKey( Binary key )
	{
		MUST( key.size() == 32 );
		reset();
		if( workingKey == null )
		{
			workingKey = new int[ 8 ];
		}
		for( int i = 0; i < 8; ++i )
		{
			workingKey[ i ] = key.getIntLE( i << 2 );
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void setIV( Binary IV )
	{
		macIV = IV.getBytes();
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public void reset()
	{
		Arrays.fill( buf, (byte)0 );
		bufOff = 0;
		firstStep = true;
	}

	public String getAlgorithmName()
	{
		return "GOST28147Mac";
	}

	public int getMacSize()
	{
		return macSize;
	}

	private int gost28147_mainStep( int n1, int key )
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

		return om << 11 | om >>> (32 - 11); // 11-leftshift
	}

	private void gost28147MacFunc( int[] workingKey, byte[] in, int inOff, byte[] out, int outOff )
	{
		int N1, N2, tmp; //tmp -> for saving N1
		N1 = bytesToint( in, inOff );
		N2 = bytesToint( in, inOff + 4 );

		for( int k = 0; k < 2; k++ ) // 1-16 steps
		{
			for( int j = 0; j < 8; j++ )
			{
				tmp = N1;
				N1 = N2 ^ gost28147_mainStep( N1, workingKey[ j ] ); // CM2
				N2 = tmp;
			}
		}

		intTobytes( N1, out, outOff );
		intTobytes( N2, out, outOff + 4 );
	}

	//array of bytes to type int
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

	private byte[] CM5func( byte[] buf, int bufOff, byte[] mac )
	{
		byte[] sum = new byte[ buf.length - bufOff ];

		System.arraycopy( buf, bufOff, sum, 0, mac.length );

		for( int i = 0; i != mac.length; i++ )
		{
			sum[ i ] = (byte)(sum[ i ] ^ mac[ i ]);
		}

		return sum;
	}

	public void update( byte in ) throws IllegalStateException
	{
		if( bufOff == buf.length )
		{
			byte[] sumbuf = new byte[ buf.length ];
			System.arraycopy( buf, 0, sumbuf, 0, mac.length );

			if( firstStep )
			{
				firstStep = false;
				if( macIV != null )
				{
					sumbuf = CM5func( buf, 0, macIV );
				}
			}
			else
			{
				sumbuf = CM5func( buf, 0, mac );
			}

			gost28147MacFunc( workingKey, sumbuf, 0, mac, 0 );
			bufOff = 0;
		}

		buf[ bufOff++ ] = in;
	}

	public void update( byte[] in, int inOff, int len )
	{
		MUST( len >= 0, "Can't have a negative input length" );

		int gapLen = blockSize - bufOff;

		if( len > gapLen )
		{
			System.arraycopy( in, inOff, buf, bufOff, gapLen );

			byte[] sumbuf = new byte[ buf.length ];
			System.arraycopy( buf, 0, sumbuf, 0, mac.length );

			if( firstStep )
			{
				firstStep = false;
				if( macIV != null )
				{
					sumbuf = CM5func( buf, 0, macIV );
				}
			}
			else
			{
				sumbuf = CM5func( buf, 0, mac );
			}

			gost28147MacFunc( workingKey, sumbuf, 0, mac, 0 );

			bufOff = 0;
			len -= gapLen;
			inOff += gapLen;

			while( len > blockSize )
			{
				sumbuf = CM5func( in, inOff, mac );
				gost28147MacFunc( workingKey, sumbuf, 0, mac, 0 );

				len -= blockSize;
				inOff += blockSize;
			}
		}

		System.arraycopy( in, inOff, buf, bufOff, len );

		bufOff += len;
	}

	public int doFinal( byte[] out, int outOff )
	{
		//padding with zero
		while( bufOff < blockSize )
		{
			buf[ bufOff ] = 0;
			bufOff++;
		}

		byte[] sumbuf = new byte[ buf.length ];
		System.arraycopy( buf, 0, sumbuf, 0, mac.length );

		if( firstStep )
		{
			firstStep = false;
		}
		else
		{
			sumbuf = CM5func( buf, 0, mac );
		}

		gost28147MacFunc( workingKey, sumbuf, 0, mac, 0 );
		System.arraycopy( mac, (mac.length / 2) - macSize, out, outOff, macSize );
		reset();

		return macSize;
	}

}
