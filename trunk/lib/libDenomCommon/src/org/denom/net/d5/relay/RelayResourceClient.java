// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5.relay;

import org.denom.Binary;
import org.denom.Ex;
import org.denom.net.d5.*;
import org.denom.format.BinBuilder;

import static org.denom.Binary.Bin;

// ----------------------------------------------------------------------------------------------------------------
/**
 * Client to work with Denom Relay server as Resource.
 */
public abstract class RelayResourceClient extends D5ReverseClient
{
	private final String name;

	// -----------------------------------------------------------------------------------------------------------------
	public RelayResourceClient( String resourceName )
	{
		this.name = resourceName;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public String getResourceName()
	{
		return name;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	protected Binary dispatch( int commandCode, Binary commandBuf )
	{
		switch( commandCode )
		{
			case D5Command.ENUM_COMMANDS : return cmdEnumCommands( commandBuf );
			case RelayCmd.WHO_ARE_YOU    : return cmdWhoAreYou( commandBuf );
			case RelayCmd.SEND           : return cmdSend( commandBuf );

			default:
				throw new Ex( D5Response.STATUS_COMMAND_NOT_SUPPORTED );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary cmdEnumCommands( Binary commandBuf )
	{
		Binary b = Bin();
		b.addInt( D5Command.ENUM_COMMANDS );
		b.addInt( RelayCmd.WHO_ARE_YOU );
		b.addInt( RelayCmd.SEND );

		return b;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	private Binary cmdWhoAreYou( Binary commandBuf )
	{
		return new BinBuilder().append( name ).getResult();
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	protected abstract Binary cmdSend( Binary commandBuf );
}