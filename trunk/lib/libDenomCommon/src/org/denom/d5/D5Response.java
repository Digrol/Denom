// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5;

import org.denom.*;

import static org.denom.Ex.MUST;

// ----------------------------------------------------------------------------------------------------------------
/**
 * DSDS Struct:
 * 
 * struct D5Response
 * {
 *     int index;
 *     int code;
 *     int status;
 *     Binary data;
 * }
 *
 * Class limit - data length can't be more than 2^31-1 (Integer.MAX_VALUE).
 */
public class D5Response
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Common Response Codes
	 */
	public final static int ENUM_COMMANDS = 0xA0000001;
	public final static int EXEC_TOKEN    = 0xA0FFFFFF;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Common status codes.
	 */
	public final static int STATUS_OK                    = 0x00000000;
	public final static int STATUS_UNKNOWN_ERROR         = 0xFFFFFFFF;
	public final static int STATUS_COMMAND_NOT_SUPPORTED = 0xE0000001;
	public final static int STATUS_WRONG_SYNTAX          = 0xE0000002;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Ordinal number of command in session.
	 */
	public int index;

	/**
	 * D5Response.code = D5Command.code - 0x20000000  (0xCXXXXXXX -> 0xAXXXXXXX).
	 */
	public int code;

	/**
	 * Status of command execution.
	 */
	public int status;

	/**
	 * Response data.
	 */
	public Binary data = new Binary();


	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Default constructor. All fields - zeroes or empty.
	 */
	public D5Response() {}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param data - Data field of response. Data will be copied.
	 * If you don't want to copy 'data', then fill fields manually.
	 */
	public D5Response( int index, int responseCode, int status, final Binary data )
	{
		this.index = index;
		this.code = responseCode;
		this.status = status;
		this.data = data.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Parse byte array, according to D5 Response syntax.
	 * @param bin - byte array with serialize 'D5 Response'.
	 * @return - true if decoding was successful, false - wrong syntax.
	 */
	public boolean decode( final Binary resp )
	{
		this.data.clear();

		if( resp.size() < 16 )
		{
			return false;
		}

		this.index = resp.getIntBE( 0 );
		this.code = resp.getIntBE( 4 );
		this.status = resp.getIntBE( 8 );

		int length = resp.getIntBE( 12 );
		if( (length != (resp.size() - 16)) )
		{
			return false;
		}

		if( length != 0 )
		{
			this.data.assign( resp, 16, length );
		}

		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Serialize D5 Response.
	 * Clears 'bin' at first.
	 * @param bin - [out] D5 Response in serialized form.
	 */
	public void encode( Binary resp )
	{
		resp.clear();
		int dataLen = this.data.size();
		resp.resize( 16 + dataLen );
		resp.setInt( 0, this.index );
		resp.setInt( 4, this.code );
		resp.setInt( 8, this.status );
		resp.setInt( 12, dataLen );
		resp.set( 16, this.data, 0, dataLen );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public boolean equals( Object obj )
	{
		if( obj instanceof D5Response )
		{
			D5Response other = (D5Response)obj;
			return (this.index == other.index) && (this.code == other.code) && (this.status == other.status)
				&& this.data.equals( other.data );
		}
		return false;
	}

	// =================================================================================================================
	/**
	 * Parse D5Response on command 'ENUM COMMANDS'.
	 * @return list of commands, supported by entity (server).
	 */
	public int[] parseEnumCommands()
	{
		MUST( code == D5Response.ENUM_COMMANDS, "Wrong 'D5 Response Code' in ENUM COMMANDS" );
		MUST( data.size() % 4 == 0, "Wrong response syntax in D5 Command 'ENUM COMMANDS'");

		int[] cmdList = new int[ data.size() >> 2 ];
		int offset = 0;
		int i = 0;
		while( offset < data.size() )
		{
			cmdList[ i ] = data.getIntBE( offset );
			offset += 4;
			++i;
		}
		return cmdList;
	}

}