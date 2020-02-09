// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.D5;

import org.denom.*;

// ----------------------------------------------------------------------------------------------------------------
/**
 * DSDS Struct:
 * 
 * struct D5Command
 * {
 *     int index;
 *     int code;
 *     Binary data;
 * }
 *
 * Class limit - total command length can't be more than 2^31-1 (Integer.MAX_VALUE).
 */
public class D5Command
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Command Codes
	 */
	public final static int ENUM_COMMANDS = 0xC0000001;
	public final static int STOP_SERVER   = 0xC0FFFFFF;

	// -----------------------------------------------------------------------------------------------------------------

	/**
	 * Ordinal number of command in session.
	 */
	public int index;

	public int code;

	/**
	 * Length = data.size()
	 */
	public Binary data = new Binary();


	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * All fields = zeroes (empty).
	 */
	public D5Command() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param data - Data field of command. Data will be copied.
	 * If you don't want to copy 'data', then fill fields manually.
	 */
	public D5Command( int index, int code, final Binary data )
	{
		this.index = index;
		this.code = code;
		this.data.assign( data );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Parse byte array, according to D5 Command syntax.
	 * @param bin - byte array.
	 * @return - true if decoding success, false - wrong syntax.
	 */
	public boolean decode( final Binary bin )
	{
		this.data.clear();

		if( bin.size() < 12 )
		{
			return false;
		}

		this.index = bin.getIntBE( 0 );
		this.code = bin.getIntBE( 4 );

		int length = bin.getIntBE( 8 );
		if( (length != (bin.size() - 12)) )
		{
			return false;
		}

		if( length != 0 )
		{
			this.data.assign( bin, 12, length );
		}

		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Serialize D5 Command.
	 * Clears 'bin' at first.
	 * @param bin - [out] D5 Command in serialized form.
	 */
	public void encode( Binary bin )
	{
		bin.clear();
		int length = data.size();
		bin.resize( 12 + length );

		bin.setInt( 0, this.index );
		bin.setInt( 4, this.code );
		bin.setInt( 8, length );
		bin.set( 12, this.data, 0, length );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public boolean equals( Object obj )
	{
		if( obj instanceof D5Command )
		{
			D5Command other = (D5Command)obj;
			return (this.index == other.index) && (this.code == other.code) && this.data.equals( other.data );
		}
		return false;
	}
}