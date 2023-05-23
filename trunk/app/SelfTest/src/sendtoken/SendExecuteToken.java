// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package sendtoken;

import org.denom.Binary;
import org.denom.d5.*;

import static org.denom.Binary.*;

/**
 * Send token from file to D5 Server.
 * All params in command line.
 */
public class SendExecuteToken
{
	public static void main( String[] args )
	{
		String tokenFilename = "";
		String host = "";
		int port = 0;
		if( args.length == 3 )
		{
			tokenFilename = args[0];
			host = args[1];
			port = Integer.parseInt( args[2] );
		}
		else
		{
			System.out.println( "Usage: java -jar SendExecuteToken.jar token_filename host port" );
			System.exit( 1 );
		}

		try( D5Client client = new D5Client( host, port, 2 ) )
		{
			Binary token = Bin().loadFromFile( tokenFilename );
			client.command( D5Command.EXECUTE_TOKEN, token );
		}

		System.out.println( "OK" );
	}
}
