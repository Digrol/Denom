// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import org.denom.Binary;

import static org.denom.Ex.MUST;

/**
 * Cryptographic hash function SHA-512/t.
 * Differences from SHA-512: Specific IV calculation, variable hash size.
 */
public class SHA512t extends SHA512
{
	private int hashSizeBits;
	private long[] IV = new long[ 8 ];

	// -----------------------------------------------------------------------------------------------------------------
	public SHA512t()
	{
		this( 256 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public SHA512t( int hashSizeBits )
	{
		super( 0 );
		
		MUST( (hashSizeBits < 512) && (hashSizeBits > 0) && ((hashSizeBits & 7) == 0),
				"hashSize needs to be a multiple of 8 and less than 512"  );
		MUST( hashSizeBits != 384, "Wrong hashSize - use SHA384 instead" );

		this.hashSizeBits = hashSizeBits;
		calcIV();
		reset();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String name()
	{
		return "SHA-512/" + Integer.toString( hashSizeBits );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int size()
	{
		return hashSizeBits >>> 3; // in bytes
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SHA512t clone()
	{
		return new SHA512t( hashSizeBits );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void calcIV()
	{
		// SHA-512 IV constants XORed with 0x
		H[0] = 0xcfac43c256196cadL;
		H[1] = 0x1ec20b20216f029eL;
		H[2] = 0x99cb56d75b315d8eL;
		H[3] = 0x00ea509ffab89354L;
		H[4] = 0xf4abf7da08432774L;
		H[5] = 0x3ea0cd298e9bc9baL;
		H[6] = 0xba267c0e5ee418ceL;
		H[7] = 0xfe4568bcb6db84dcL;

		// calc hash for String: 'SHA-512/ttt'
		super.process( new Binary( name().getBytes() ) );
		super.finish();

		System.arraycopy( H, 0, IV, 0, H.length );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void reset()
	{
		super.reset();
		System.arraycopy( IV, 0, H, 0, H.length );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary getHash()
	{
		return super.getHash().first( hashSizeBits >>> 3 );
	}
}
