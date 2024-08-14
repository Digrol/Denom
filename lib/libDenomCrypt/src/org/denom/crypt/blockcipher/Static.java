package org.denom.crypt.blockcipher;

public final class Static
{
	public static int bigEndianToInt( byte[] bs, int off )
	{
		int n = bs[ off ] << 24;
		n |= (bs[ ++off ] & 0xff) << 16;
		n |= (bs[ ++off ] & 0xff) << 8;
		n |= (bs[ ++off ] & 0xff);
		return n;
	}

	public static void intToBigEndian( int n, byte[] bs, int off )
	{
		bs[ off ] = (byte)(n >>> 24);
		bs[ ++off ] = (byte)(n >>> 16);
		bs[ ++off ] = (byte)(n >>> 8);
		bs[ ++off ] = (byte)(n);
	}

	public static byte[] intToBigEndian( int[] ns )
	{
		byte[] bs = new byte[ 4 * ns.length ];
		intToBigEndian( ns, bs, 0 );
		return bs;
	}

	public static void intToBigEndian( int[] ns, byte[] bs, int off )
	{
		for( int i = 0; i < ns.length; ++i )
		{
			intToBigEndian( ns[ i ], bs, off );
			off += 4;
		}
	}

	public static int littleEndianToInt( byte[] bs, int off )
	{
		int n = bs[ off ] & 0xff;
		n |= (bs[ ++off ] & 0xff) << 8;
		n |= (bs[ ++off ] & 0xff) << 16;
		n |= bs[ ++off ] << 24;
		return n;
	}

	public static void littleEndianToInt( byte[] bs, int bOff, int[] ns, int nOff, int count )
	{
		for( int i = 0; i < count; ++i )
		{
			ns[ nOff + i ] = littleEndianToInt( bs, bOff );
			bOff += 4;
		}
	}

	public static int[] littleEndianToInt( byte[] bs, int off, int count )
	{
		int[] ns = new int[ count ];
		for( int i = 0; i < ns.length; ++i )
		{
			ns[ i ] = littleEndianToInt( bs, off );
			off += 4;
		}
		return ns;
	}

	public static void intToLittleEndian( int n, byte[] bs, int off )
	{
		bs[ off ] = (byte)(n);
		bs[ ++off ] = (byte)(n >>> 8);
		bs[ ++off ] = (byte)(n >>> 16);
		bs[ ++off ] = (byte)(n >>> 24);
	}


	public static void intToLittleEndian( int[] ns, byte[] bs, int off )
	{
		for( int i = 0; i < ns.length; ++i )
		{
			intToLittleEndian( ns[ i ], bs, off );
			off += 4;
		}
	}


}