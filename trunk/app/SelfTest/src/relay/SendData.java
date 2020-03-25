// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package relay;

import java.util.concurrent.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.net.d5.relay.RelayUserClient;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Проверяем отправку данных.
 */
public class SendData
{
	int THREADS_NUMBER = 1;
	int COMMANDS_NUMBER = 10;
	int DATA_SIZE = 1000000;

	LogConsole log;
	ExecutorService workerExecutor;

	//ILog debugLog = new LogTime( new LogFile( ".log", false ) );

	//String host = "localhost";
	//String host = "demo.sls.team";
	String host = "denom.org";
	//String host = "172.16.0.94";
	int resourcePort = 4211;
	int userPort = 4210;
	String resourceName = "AcceptData";

	// -----------------------------------------------------------------------------------------------------------------
	SendData()
	{
		log = new LogConsole();

		ExecutorService workerExecutor = Executors.newFixedThreadPool( THREADS_NUMBER,
			new ThreadFactoryNamed( "SendData", Thread.NORM_PRIORITY, 0 ) );

		Ticker ticker = new Ticker();

		for( int i = 0; i < THREADS_NUMBER; ++i )
		{
			final int ii = i + 1;
			workerExecutor.execute( () -> sendData( ii ) );
		}

		workerExecutor.shutdown();
		try
		{
			MUST( workerExecutor.awaitTermination( 1000, TimeUnit.SECONDS ), "Can't stop workerExecutor" );
		}
		catch( InterruptedException ex ) {}
		
		log.writeln( "Total time: " + ticker.getDiffMs() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void sendData( int taskID )
	{
		try( RelayUserClient client = new RelayUserClient( host, userPort ) )
		{
			//client.setLog( log );

			log.writeln( "Resources on Relay:" );
			for( String s : client.cmdListResources( "" ) )
			{
				log.writeln( "    " + s );
			}
			
			Ticker t = new Ticker();
			long resourceID = client.cmdIsResourcePresent( resourceName );
			log.writeln( taskID + " -  cmdIsResourcePresent: " + t.getDiffMs() + " ms" );
			MUST( resourceID != 0, "No Resource with name: " + resourceName );


			t.restart();
			client.cmdSend( resourceID, Bin(DATA_SIZE, 0xA5) );
			log.writeln( taskID + " -  cmdSend: " + t.getDiffMs() + " ms" );

			t.restart();
			client.cmdSendTo( resourceName,  Bin(DATA_SIZE, 0xB7) );
			log.writeln( taskID + " -  cmdSendTo: " + t.getDiffMs() + " ms" );

			log.writeln( taskID + " -  Send " + COMMANDS_NUMBER + " commands with " + DATA_SIZE + " bytes:" );
			Binary data = Bin( DATA_SIZE, taskID );

			t.restart();
			for( int i = 0; i < COMMANDS_NUMBER; ++i )
			{
				Binary resp = client.cmdSend( resourceID, data );
				MUST( resp.get( 0 ) == (taskID & 0xFF), "Wrong Response" );
			}
			log.writeln( taskID + " -  Total bytes: " + COMMANDS_NUMBER * DATA_SIZE + ". Time: " + t.getDiffMs() + " ms" );
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.RED_I, ex.toString() );
		}
	}
	
	
	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new SendData();
	}
}
