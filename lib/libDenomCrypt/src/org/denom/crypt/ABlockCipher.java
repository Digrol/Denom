// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt;

import org.denom.Binary;

public abstract class ABlockCipher
{
	/**
	 * Create copy of block cipher with same key.
	 */
	public abstract ABlockCipher clone();

	public abstract int getBlockSize();

	public abstract  int getKeySize();

	public abstract Binary generateKey();

	public abstract ABlockCipher setKey( final Binary key );

	public abstract Binary getKey();


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
}
