// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package relaychat;

import org.denom.log.*;
import org.denom.format.*;
import org.denom.d5.relay.*;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Пример защищенного чата на базе D5Relay.
 */
public class ExampleChatMain
{
	LogColoredConsoleWindow messageLog;
	ExampleResourceChat resourceChat;
	ILog debugLog = new LogTime( new LogFile( "RelayChat.log", false ) );
	
	String host;
	int resourcePort;
	int userPort;

	RelaySigner myKey;
	RelaySigner remoteKey;

	// -----------------------------------------------------------------------------------------------------------------
	ExampleChatMain()
	{
		Runtime.getRuntime().addShutdownHook( new Thread( this::onCloseProgram ) );

		messageLog = new LogColoredConsoleWindow( "Приём сообщений" );
		messageLog.setDefaultColor( Colors.CYAN_I );

		try
		{
			JSONObject jo = new JSONObject().loadWithComments( "RelayChat.config" );
			host = jo.getString( "Host" );
			resourcePort = jo.getInt("Resource Port");
			userPort = jo.getInt("User Port");

			String myName = jo.getString("My Name");
			messageLog.consoleWindow.setTitle( "My name: " + myName );

			myKey = new RelaySigner();
			myKey.readPrivateKeyFromJSON( jo.getJSONObject( "My Key" ) );

			remoteKey = new RelaySigner();
			remoteKey.readPublicKeyFromJSON(jo.getJSONObject( "Remote Key" ) );


			resourceChat = new ExampleResourceChat( myKey, myName, "", messageLog );
			resourceChat.setLog( debugLog );
			resourceChat.connect( host, resourcePort, 15 );


			sendMessagesOnEnter();
		}
		catch( Throwable ex )
		{
			messageLog.writeln( Colors.RED_I, ex.toString() );
		}
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	private void sendMessagesOnEnter()
	{
		ExampleChatUser client = new ExampleChatUser( host, userPort, messageLog );
		boolean connectedToResource = false;
		
		while( true )
		{
			try
			{
				String message = messageLog.readln();
				if( message.equals( ":exit:" ) )
					break;

				if( !connectedToResource )
				{
					client.cmdGetResourceInfo( remoteKey.getPublicKey() );
					client.sendInitSM( myKey );
					connectedToResource = true;
				}

				client.sendMessage( message );
			}
			catch( Throwable ex )
			{
				messageLog.writeln( Colors.RED_I, ex.toString() );
			}
		}

		client.close();
	}

	// -----------------------------------------------------------------------------------------------------------------
	void onCloseProgram()
	{
		resourceChat.close();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new ExampleChatMain();
	}
}
