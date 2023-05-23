// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5.relay;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import org.denom.*;
import org.denom.log.*;
import org.denom.net.*;

import static org.denom.Ex.*;

/**
 * Server that accepts 'Resources' and 'Users' and transmit messages from Users to Resources.
 */
class Relay
{
	// Длина публичного ключа в байтах
	public final static int PUBLIC_KEY_SIZE = 32;

	final RelayOptions options;
	private ILog log;

	private ExecutorService workerExecutor;

	private TCPServer serverUsers = null;
	private TCPServer serverResources = null;

	private Consumer<Binary> shutdownConsumer;

	AtomicLong lastUserID = new AtomicLong();
	AtomicLong lastResourceID = new AtomicLong();

	boolean started = false;

	Map<Binary, RelayResourceSession> resources = null;

	// -----------------------------------------------------------------------------------------------------------------
	Relay( RelayOptions options, Consumer<Binary> shutdownConsumer, ILog log )
	{
		this.shutdownConsumer = shutdownConsumer;
		this.options = options;
		this.log = log;
	}

	// -----------------------------------------------------------------------------------------------------------------
	void startServer()
	{
		MUST( !started, "DenomRelay already started" );

		log.writeln( Colors.GRAY, "DenomRelay starting..." );

		resources = new HashMap<>();

		workerExecutor = Executors.newFixedThreadPool( options.workerThreads,
			new ThreadFactoryNamed( "DenomRelayWorker", Thread.NORM_PRIORITY, 0, false ) );

		log.writeln( Colors.GRAY, "Start listening Resources on " + options.host + ":" + options.resource.port );
		serverResources = new TCPServer( log, options.host, options.resource.port,
				new RelayResourceSession( this, log ) );
		
		log.writeln( Colors.GRAY, "Start listening Users on " + options.host + ":" + options.userPort );
		serverUsers = new TCPServer( log, options.host, options.userPort,
				new RelayUserSession( this, log ) );

		log.writeln( Colors.GRAY, "DenomRelay started." );
		started = true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	void stopServer()
	{
		if( !started )
			return;

		serverUsers.close();
		serverUsers = null;

		serverResources.close();
		serverResources = null;

		resources.clear();

		workerExecutor.shutdownNow();
		try
		{
			MUST( workerExecutor.awaitTermination( 3, TimeUnit.SECONDS ), "Can't stop workerExecutor" );
		}
		catch( InterruptedException ex ) {}
		workerExecutor = null;
		
		started = false;
		log.writeln( Colors.DARK_GRAY, "DenomRelay stopped." );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void doWork( Runnable someWork )
	{
		workerExecutor.execute( someWork );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public void executeToken( Binary token )
	{
		shutdownConsumer.accept( token );
	}

}
