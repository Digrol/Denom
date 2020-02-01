package org.denom.crypt.blockcipher;

import java.util.Arrays;
import org.denom.Binary;

import static org.denom.Ex.MUST;

/**
 * A wrapper class that allows block ciphers to be used to process data in a piecemeal fashion. The
 * BufferedBlockCipher outputs a block only when the buffer is full and more data is being added, or
 * on a doFinal.
 * <p>
 * Note: in the case where the underlying cipher is either a CFB cipher or an OFB one the last block
 * may not be a multiple of the block size.
 */
public class BufferedBlockCipher
{
	protected byte[] buf;
	protected int bufOff;

	protected boolean forEncryption;
	protected BlockCipher cipher;

	protected boolean partialBlockOkay;

	protected BufferedBlockCipher() {}

	/**
	 * Create a buffered block cipher without padding.
	 * @param cipher the underlying block cipher this buffering object wraps.
	 */
	public BufferedBlockCipher( BlockCipher cipher )
	{
		this.cipher = cipher;
		buf = new byte[ cipher.getBlockSize() ];
		bufOff = 0;

		if( cipher instanceof StreamCipher )
		{
			partialBlockOkay = true;
		}
	}

	/**
	 * initialise the cipher.
	 *
	 * @param forEncryption if true the cipher is initialised for encryption, if false for
	 * decryption.
	 * @param params the key and other data required by the cipher.
	 * @exception IllegalArgumentException if the params argument is inappropriate.
	 */
	public void init( boolean forEncryption, CipherParameters params ) throws IllegalArgumentException
	{
		this.forEncryption = forEncryption;
		reset();
		cipher.init( forEncryption, params );
	}

    /**
     * return the blocksize for the underlying cipher.
     *
     * @return the blocksize for the underlying cipher.
     */
    public int getBlockSize()
    {
        return cipher.getBlockSize();
    }

	/**
	 * return the size of the output buffer required for an update an input of len bytes.
	 *
	 * @param len the length of the input.
	 * @return the space required to accommodate a call to update with len bytes of input.
	 */
	public int getUpdateOutputSize( int len )
	{
		int total = len + bufOff;
		int leftOver = total % buf.length;
		return total - leftOver;
	}

	/**
	 * process an array of bytes, producing output if necessary.
	 *
	 * @param in the input byte array.
	 * @param inOff the offset at which the input data starts.
	 * @param len the number of bytes to be copied out of the input array.
	 * @param out the space for any output that might be produced.
	 * @param outOff the offset from which the output will be copied.
	 * @return the number of output bytes copied to out.
	 */
	public int processBytes( byte[] in, int inOff, int len, byte[] out, int outOff )
	{
		MUST( len >= 0 );

		int blockSize = getBlockSize();
		int length = getUpdateOutputSize( len );

		if( length > 0 )
		{
			MUST( (outOff + length) <= out.length );
		}

		int resultLen = 0;
		int gapLen = buf.length - bufOff;

		if( len > gapLen )
		{
			System.arraycopy( in, inOff, buf, bufOff, gapLen );

			resultLen += cipher.processBlock( buf, 0, out, outOff );

			bufOff = 0;
			len -= gapLen;
			inOff += gapLen;

			while( len > buf.length )
			{
				resultLen += cipher.processBlock( in, inOff, out, outOff + resultLen );

				len -= blockSize;
				inOff += blockSize;
			}
		}

		System.arraycopy( in, inOff, buf, bufOff, len );

		bufOff += len;

		if( bufOff == buf.length )
		{
			resultLen += cipher.processBlock( buf, 0, out, outOff + resultLen );
			bufOff = 0;
		}

		return resultLen;
	}

	/**
	 * Process the last block in the buffer.
	 * @param out the array the block currently being held is copied into.
	 * @param outOff the offset at which the copying starts.
	 * @return the number of output bytes copied to out.
	 */
	public int doFinal( byte[] out, int outOff )
	{
		try
		{
			int resultLen = 0;
			MUST( (outOff + bufOff) <= out.length );

			if( bufOff != 0 )
			{
				MUST( partialBlockOkay, "data not block size aligned" );

				cipher.processBlock( buf, 0, buf, 0 );
				resultLen = bufOff;
				bufOff = 0;
				System.arraycopy( buf, 0, out, outOff, resultLen );
			}

			return resultLen;
		}
		finally
		{
			reset();
		}
	}

	/**
	 * Reset the buffer and cipher. After resetting the object is in the same state as it was after
	 * the last init (if there was one).
	 */
	public void reset()
	{
		Arrays.fill( buf, (byte)0 );
		bufOff = 0;
		cipher.reset();
	}

	public Binary encrypt( CipherParameters params, Binary data )
	{
		this.init( true, params );
		Binary crypt = new Binary( data.size() );
		int len1 = processBytes( data.getDataRef(), 0, data.size(), crypt.getDataRef(), 0 );
		doFinal( crypt.getDataRef(), len1 );
		return crypt;
	}

	public Binary decrypt( CipherParameters params, Binary crypt )
	{
		this.init( false, params );
		Binary data = new Binary( crypt.size() );
		int len1 = processBytes( crypt.getDataRef(), 0, crypt.size(), data.getDataRef(), 0 );
		doFinal( data.getDataRef(), len1 );
		return data;
	}
}
