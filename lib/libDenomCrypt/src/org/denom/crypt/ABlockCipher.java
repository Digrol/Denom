// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt;

import org.denom.Binary;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

public abstract class ABlockCipher
{
	/**
	 * Create copy of block cipher with same key.
	 */
	public abstract ABlockCipher clone();

	public abstract int getBlockSize();

	public abstract int getKeySize();

	public abstract Binary generateKey();

	public abstract ABlockCipher setKey( final Binary key );

	public abstract Binary getKey();

	/**
	 * @param block [ getBlockSize() ].
	 */
	public abstract void encryptBlock( Binary block );
	public abstract void decryptBlock( Binary block );


	public abstract Binary encrypt( final Binary data, CryptoMode cryptMode, AlignMode alignMode );
	public abstract Binary encrypt( final Binary data, CryptoMode cryptMode, AlignMode alignMode, final Binary iv );

	public abstract Binary decrypt( final Binary crypt, CryptoMode cryptMode, AlignMode alignMode );
	public abstract Binary decrypt( final Binary crypt, CryptoMode cryptMode, AlignMode alignMode, final Binary iv );


	public abstract void encryptFirst( final Binary data, Binary crypt, CryptoMode cryptMode, AlignMode alignMode, final Binary iv );
	public abstract void encryptNext( final Binary data, Binary crypt );
	public abstract void encryptLast( final Binary data, Binary crypt );

	public abstract void decryptFirst( final Binary crypt, Binary data, CryptoMode cryptMode, AlignMode alignMode, final Binary iv );
	public abstract void decryptNext( final Binary crypt, Binary data );
	public abstract void decryptLast( final Binary crypt, Binary data );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Counter (CTR) mode -- ISO 10116:2006.
	 * Same algorithm for encryption and decryption.
	 * @param P - data to process.
	 * @param SV - Starting Value [getBlockSize()]
	 * @param JBytes - size of part (in bytes) <= getBlockSize()
	 * @return C - cryptogram (if P - plain) or plain text (if P - cryptogram)
	 */
	public Binary cryptCTR( final Binary P, final Binary SV, int JBytes )
	{
		int blockSize = getBlockSize();
		MUST( (JBytes > 0) && (JBytes <= blockSize) && (SV.size() == blockSize), "Wrong params for CTR" );

		Binary Qi = SV.clone();
		Binary Ei = Bin( blockSize );
		Binary C = Bin( P.size() );
		byte[] CArr = C.getDataRef();
		byte[] PArr = P.getDataRef();
		byte[] EArr = Ei.getDataRef();

		int PSize = P.size();
		for( int offset = 0; offset < PSize; offset += JBytes )
		{
			Ei.assign( Qi );
			encryptBlock( Ei );

			// Ci = Ei xor Pi
			int partSize = Math.min( JBytes, PSize - offset );
			for( int i = 0; i < partSize; ++i )
			{
				CArr[ offset + i ] = (byte)(PArr[ offset + i ] ^ EArr[ i ]);
			}

			Qi.increment();
		}

		return C;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary cryptCTR( final Binary P, final Binary SV )
	{
		return cryptCTR( P, SV, getBlockSize() );
	}
}
