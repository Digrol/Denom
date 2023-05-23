// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package relaychat;

import org.denom.format.*;
import org.denom.log.*;
import org.denom.d5.relay.*;

// -----------------------------------------------------------------------------------------------------------------
class ExampleChatUser extends RelayUserClient
{
	final ILog messageLog;

	ExampleChatUser( String host, int port, ILog messageLog )
	{
		super( host, port );
		this.messageLog = messageLog;
	}

	void sendMessage( String message)
	{
		BinBuilder bb = new BinBuilder();
		bb.append( message );
		this.cmdSendEncrypted( 0xCCDD0001, bb.getResult() );
		messageLog.writeln( Colors.GREEN_I, "Я: " + message );
	}
}
