// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package relay;

import java.util.concurrent.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.d5.relay.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Проверяем отправку данных.
 */
public class SendData
{
	public final static int CMD_SEND_SOME_DATA = 0xCDD01122;
	
	int THREADS_NUMBER = 4;
	long COMMANDS_NUMBER = 100;
	int DATA_SIZE = 100000;

	LogConsole log;
	ExecutorService workerExecutor;

	//ILog debugLog = new LogTime( new LogFile( ".log", false ) );

	//String host = "localhost";
	String host = "denom.org";
	int userPort = 4210;

	//String host = "test.sls.team";
	//int userPort = 11265;

	Binary resourcePublicKey = Bin( "59E3EBDA2A5F0247222A7C67D437BFE3E5E46DAF2C2AB284EA49FDC40D8CDB32" );

	// -----------------------------------------------------------------------------------------------------------------
	SendData()
	{
		log = new LogConsole();

		ExecutorService workerExecutor = Executors.newFixedThreadPool( THREADS_NUMBER,
			new ThreadFactoryNamed( "SendData", Thread.NORM_PRIORITY, 0, true ) );

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

			Ticker t = new Ticker();
			client.cmdGetResourceInfo( resourcePublicKey );
			log.writeln( taskID + " -  cmdIsResourcePresent: " + t.getDiffMs() + " ms" );
			MUST( client.resourceInfo.resourceHandle != 0, "No Resource with key: " + resourcePublicKey.Hex() );

			RelaySigner myKey = new RelaySigner();
			myKey.generateKeyPair();
			client.sendInitSM( myKey );

			Binary data = Bin( DATA_SIZE, taskID );
			t.restart();
			for( int i = 0; i < COMMANDS_NUMBER; ++i )
			{
				Binary resp = client.cmdSendEncrypted( CMD_SEND_SOME_DATA, data );
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
