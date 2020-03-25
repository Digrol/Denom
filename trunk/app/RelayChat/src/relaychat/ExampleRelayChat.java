// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package relaychat;

import static org.denom.Binary.Bin;

import org.denom.Binary;
import org.denom.log.*;
import org.denom.format.*;
import org.denom.net.d5.D5Client;
import org.denom.net.d5.relay.RelayCmd;

// -----------------------------------------------------------------------------------------------------------------
public class ExampleRelayChat
{
	LogColoredConsoleWindow messageLog;
	RelayResourceChat resourceChat;
	ILog debugLog = new LogTime( new LogFile( "RelayChat.log", false ) );
	
	String host;
	int resourcePort;
	int userPort;
	String myName;
	String remoteName;

	// -----------------------------------------------------------------------------------------------------------------
	ExampleRelayChat()
	{
		Runtime.getRuntime().addShutdownHook( new Thread( () -> 
		{
			this.onClose();
		}));

		messageLog = new LogColoredConsoleWindow( "Приём сообщений" );

		try
		{
			loadConfig();
			listenMessages();
			sendMessagesOnEnter();
		}
		catch( Throwable ex )
		{
			messageLog.writeln( Colors.RED_I, ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void loadConfig()
	{
		JSONObject jo = new JSONObject().load( "RelayChat.config" );
		host = jo.getString( "Host" );
		myName = jo.getString( "My Name" );
		remoteName = jo.getString( "Remote Name" );
		resourcePort = jo.getInt( "Resource Port" );
		userPort = jo.getInt( "User Port" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void listenMessages()
	{
		messageLog.setDefaultColor( Colors.CYAN_I );
		resourceChat = new RelayResourceChat( myName, messageLog );
		resourceChat.setLog( debugLog );
		resourceChat.connect( host, resourcePort, 150 );
		resourceChat.start();
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	private void sendMessagesOnEnter()
	{
		D5Client client = new D5Client( host, userPort, 5 );
		// client.setLog( messageLog );
	
		while( true )
		{
			try
			{
				String message = messageLog.readln();
				if( message.isEmpty() )
				{
					break;
				}
				
				Binary buf = Bin();
				BinBuilder bb = new BinBuilder( buf );
				bb.append( remoteName );
				bb.append( message );
				client.command( RelayCmd.SEND_TO, buf );
				messageLog.writeln( Colors.GREEN_I, "Я: " + message );
			}
			catch( Throwable ex )
			{
				messageLog.writeln( Colors.RED_I, ex.toString() );
			}
		}
	
		client.close();
	
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	void onClose()
	{
		resourceChat.close();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new ExampleRelayChat();
	}
}
