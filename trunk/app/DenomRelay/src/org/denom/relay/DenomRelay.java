// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.relay;

import java.util.function.Consumer;

import org.denom.*;
import org.denom.log.*;
import org.denom.net.*;

import static org.denom.Ex.*;

/**
 * Server that accepts 'Resources' and 'Users'.
 */
class DenomRelay
{
	final DenomRelayOptions options;
	private ILog log;

	private TCPServer serverUsers = null;
	private DispatcherRelayUser dispatcherRelayUser = null;

	private Consumer<Binary> shutdownConsumer;

	boolean started = false;

	// -----------------------------------------------------------------------------------------------------------------
	DenomRelay( DenomRelayOptions options, Consumer<Binary> shutdownConsumer, ILog log )
	{
		this.shutdownConsumer = shutdownConsumer;
		this.options = options;
		this.log = log;
	}

	// -----------------------------------------------------------------------------------------------------------------
	void startServer()
	{
		MUST( !started, "DenomRelay already started" );

		writeln( Colors.GRAY, "DenomRelay starting..." );

		writeln( Colors.GRAY, "Opening server port for Users on " + options.host + ":" + options.userPort );
		dispatcherRelayUser = new DispatcherRelayUser( this, options.userDispatcherThreads );
		serverUsers = new TCPServer( log, options.host, options.userPort,
				new SessionRelayUser( options.userSessionBufSize, log, dispatcherRelayUser ) );

		writeln( Colors.GRAY, "DenomRelay started." );
		started = true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	void stopServer()
	{
		if( !started )
			return;

		serverUsers.close();
		serverUsers = null;

		started = false;
		writeln( Colors.DARK_GRAY, "DenomRelay stopped" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void executeToken( Binary token )
	{
		shutdownConsumer.accept( token );
	}

	// -----------------------------------------------------------------------------------------------------------------
	synchronized void writeln( int color, String text )
	{
		log.writeln( color, text );
	}

}
