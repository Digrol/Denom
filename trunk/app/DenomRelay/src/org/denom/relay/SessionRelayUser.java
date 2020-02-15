// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.relay;

import java.nio.channels.*;

import org.denom.log.*;
import org.denom.net.TCPServer;
import org.denom.d5.*;

// -----------------------------------------------------------------------------------------------------------------
public class SessionRelayUser extends D5CommandServerSession
{

	// -----------------------------------------------------------------------------------------------------------------
	public SessionRelayUser( int bufSize, ILog log, DispatcherRelayUser dispatcher )
	{
		super( bufSize, log, dispatcher );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SessionRelayUser newInstance( TCPServer tcpProcessor, SocketChannel clientSocket )
	{
		return new SessionRelayUser( bufSize, log, dispatcher, tcpProcessor, clientSocket );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected SessionRelayUser( int bufSize, ILog log, D5CommandDispatcher commandDispatcher, TCPServer tcpProcessor, SocketChannel clientSocket )
	{
		super( bufSize, log, commandDispatcher, tcpProcessor, clientSocket );
		log.writeln( "User Session created: " + remoteAddress );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void close()
	{
		super.close();
		log.writeln( Colors.CYAN, "User Session session closed: " + remoteAddress );
	}

}