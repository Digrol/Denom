// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package relaychat;

import org.denom.Binary;
import org.denom.format.BinParser;
import org.denom.log.ILog;
import org.denom.net.d5.relay.RelayResourceClient;

// -----------------------------------------------------------------------------------------------------------------
public class RelayResourceChat extends RelayResourceClient
{
	private final ILog messageLog;
	final BinParser bp = new BinParser( null );
	
	// -----------------------------------------------------------------------------------------------------------------
	public RelayResourceChat( String resourceName, ILog messageLog )
	{
		super( resourceName );
		this.messageLog = messageLog;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected Binary cmdSend( Binary commandBuf )
	{
		bp.reset( commandBuf, 12 );
		String message = bp.getString();
		messageLog.writeln( message );

		return commandBuf.first( 12 );
	}
}
