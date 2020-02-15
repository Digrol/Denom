// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.relay;

import org.denom.*;
import org.denom.d5.*;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

// -----------------------------------------------------------------------------------------------------------------
public class DispatcherRelayUser extends D5CommandDispatcher
{
	private final DenomRelay relay;

	// -----------------------------------------------------------------------------------------------------------------
	public DispatcherRelayUser( DenomRelay relay, int threadsNumber )
	{
		super( threadsNumber );
		this.relay = relay;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected Binary dispatch( D5CommandServerSession s, D5Command command )
	{
		switch( command.code )
		{
			case D5Command.ENUM_COMMANDS   : return cmdEnumCommands();
			case D5Command.EXECUTE_TOKEN   : return cmdExecuteToken( command.data );
			default:
				THROW( D5Response.STATUS_COMMAND_NOT_SUPPORTED );
		}
		return null; // Antiwarning;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary cmdEnumCommands()
	{
		Binary b = Bin();
		b.addInt( D5Command.ENUM_COMMANDS );
		b.addInt( D5Command.EXECUTE_TOKEN );
		return b;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Административный запрос на остановку ноды и закрытие процесса.
	 */
	private Binary cmdExecuteToken( final Binary token )
	{
		relay.executeToken( token );
		return Bin();
	}

}
