// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package relaychat;

import org.denom.Binary;
import org.denom.format.BinParser;
import org.denom.log.*;
import org.denom.d5.relay.*;

// -----------------------------------------------------------------------------------------------------------------
public class ExampleResourceChat extends RelayResourceClient
{
	private final ILog messageLog;
	
	// -----------------------------------------------------------------------------------------------------------------
	public ExampleResourceChat( RelaySigner resourceKey, String resourceName, String description, ILog messageLog )
	{
		super( resourceKey, resourceName, description, 4, "RelayResourceChat" );
		this.setOnClosed( this::onClosed );
		this.setLog( messageLog );
		this.messageLog = messageLog;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected Binary dispatchSend( long userHandle, int userToResourceIndex, int commandCode, Binary data )
	{
		final BinParser bp = new BinParser( data );
		String message = bp.getString();
		messageLog.writeln( message );
		return new Binary();
	}

	// -------------------------------------------------------------------------------------------------------------
	private void onClosed()
	{
		messageLog.writeln( "Connection with Relay closed" );
	}
}