// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package relay;

import org.denom.*;
import org.denom.format.JSONObject;
import org.denom.log.*;
import org.denom.net.d5.relay.RelayResourceClient;

// -----------------------------------------------------------------------------------------------------------------
public class AcceptData
{
	ILog log;
	RelayResourceData resourceData;

	String host;
	int resourcePort;
	String resourceName;

	// -----------------------------------------------------------------------------------------------------------------
	AcceptData()
	{
		log = new LogTime( new LogFile( "AcceptData.log", false ) );
		try
		{
			JSONObject jo = new JSONObject().load( "AcceptData.config" );
			host = jo.getString( "Host" );
			resourcePort = jo.getInt( "Resource Port" );
			resourceName = jo.getString( "Name" );

			resourceData = new RelayResourceData( resourceName );
			resourceData.setLog( log );
			resourceData.setPrintCommands( jo.getBoolean( "Transport Log" ) );
			resourceData.connect( host, resourcePort, 3 );
			resourceData.start();
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.RED_I, ex.toString() );
		}
	}

	// =================================================================================================================
	class RelayResourceData extends RelayResourceClient
	{
		long acceptedDataSize = 0;
		public RelayResourceData( String resourceName )
		{
			super( resourceName );
		}

		// -------------------------------------------------------------------------------------------------------------
		@Override
		protected Binary cmdSend( Binary commandBuf )
		{
			int curDataSize = (commandBuf.size() - 16);
			acceptedDataSize += curDataSize;
			AcceptData.this.log.writeln( "Принято: " + curDataSize + ".  Всего: " + acceptedDataSize );

			Binary resp = commandBuf.first( 12 );
			if( curDataSize > 0 )
			{
				resp.addInt( 1 ).add( commandBuf.get( 17 ) );
			}

			return resp;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new AcceptData();
	}}

