// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5.relay;

import java.io.File;
import java.util.concurrent.Executors;

import org.denom.*;
import org.denom.log.*;
import org.denom.format.JSONObject;

import static org.denom.Binary.Bin;

/**
 * Entry point for starting and stopping Denom Relay.
 */
public class RelayMain
{
	private static final String CONFIG_FILENAME         = "DenomRelay.config";
	private static final String LOG_FILENAME            = "DenomRelay.log";
	private static final String SHUTDOWN_TOKEN_FILENAME = "shutdown.token";
	private Binary shutdownToken = Bin();

	private ILog log = new LogDummy();

	private RelayOptions options = new RelayOptions();
	private Relay relay = null;

	// -----------------------------------------------------------------------------------------------------------------
	private RelayMain()
	{
		loadConfig();

		if( options.fileLog )
		{
			log = new LogTime( new LogFile( LOG_FILENAME, true ) );
		}

		relay = new Relay( options, (token) -> executeShutdownToken( token ), log );

		shutdownToken.random( 32 );
		shutdownToken.saveToFile( SHUTDOWN_TOKEN_FILENAME );

		relay.startServer();

		Runtime.getRuntime().addShutdownHook( new Thread( () -> 
		{
			this.onClose();
		}));
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void loadConfig()
	{
		try
		{
			if( !new File( CONFIG_FILENAME ).exists() )
				return;

			JSONObject jo = new JSONObject().load( CONFIG_FILENAME );

			options.fromJSON( jo );
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.ERROR, ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void onClose()
	{
		try
		{
			relay.stopServer();
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.ERROR, ex.toString() );
		}

		new File( SHUTDOWN_TOKEN_FILENAME ).delete();
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	private void executeShutdownToken( Binary shutdownToken )
	{
		Executors.newSingleThreadExecutor().execute( () ->
		{
			if( shutdownToken.equals( this.shutdownToken ) )
			{
				onClose();
				System.exit( 0 );
			}
		});
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new RelayMain();
	}
}
