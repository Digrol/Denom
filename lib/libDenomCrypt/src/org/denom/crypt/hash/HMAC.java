// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import org.denom.Binary;

import static org.denom.Binary.*;
import static org.denom.Ex.MUST;

/**
 * HMAC: Keyed-Hashing for Message Authentication.
 * См. RFC 2104.
 */
public class HMAC
{
	private final int BLOCK_SIZE = 64;
	
	private final Binary IPAD = new Binary( BLOCK_SIZE, 0x36 );
	private final Binary OPAD = new Binary( BLOCK_SIZE, 0x5c );

	private Binary keyIPad = null;
	private Binary keyOPad = null;
	private IHash hash;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param hash - Алгоритм хеширования.
	 */
	public HMAC( IHash hash )
	{
		MUST( hash != null, "Алгоритм хеширования = null" );
		this.hash = hash;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param hash - Алгоритм хеширования.
	 * @param key - ключ/секрет [произвольный размер].
	 */
	public HMAC( IHash hash, Binary key )
	{
		MUST( hash != null, "Алгоритм хеширования = null" );
		this.hash = hash;
		setKey( key );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param key - ключ/секрет [произвольный размер].
	 * @return - ссылка на себя.
	 */
	public HMAC setKey( Binary key )
	{
		if( key.size() > BLOCK_SIZE )
		{
			key = hash.calc( key );
		}

		// Выравнивание ключа до размера блока
		Binary keyPadded = key.clone();
		keyPadded.resize( BLOCK_SIZE );

		keyIPad = Binary.xor( keyPadded, IPAD );
		keyOPad = Binary.xor( keyPadded, OPAD );

		return this; 
	}

	// -----------------------------------------------------------------------------------------------------------------
	public int getSize()
	{
		return hash.size();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить HMAC.
	 * @param data - Произвольные данные, для которых вычисляется HMAC.
	 */
	public Binary calc( Binary data )
	{
		MUST( keyIPad != null, "HMAC key not set" );
		Binary hash_ipad = hash.calc( Bin( keyIPad, data ) );
		Binary result = hash.calc( Bin( keyOPad, hash_ipad ) );
		return result;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public HMAC clone()
	{
		return new HMAC( this.hash.clone() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public HMAC cloneWithKey()
	{
		HMAC clone = new HMAC( this.hash.clone() );
		if( keyIPad != null )
		{
			clone.keyIPad = this.keyIPad.clone();
			clone.keyOPad = this.keyOPad.clone();
		}
		return clone;
	}

}
