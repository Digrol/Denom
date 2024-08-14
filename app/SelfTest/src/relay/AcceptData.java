// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package relay;

import org.denom.*;
import org.denom.format.JSONObject;
import org.denom.log.*;
import org.denom.d5.relay.*;

import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
public class AcceptData
{
	ILog log;
	RelayResourceAcceptData resourceAcceptData;

	String host;
	int resourcePort;

	RelaySigner myKey;

	// -----------------------------------------------------------------------------------------------------------------
	AcceptData()
	{
		log = new LogTime( new LogFile( "AcceptData.log", false ) );
		try
		{
			// ReadOptions
			JSONObject jo = new JSONObject().loadWithComments( "AcceptData.config" );
			host = jo.getString( "Host" );
			int resourcePort = jo.getInt( "Resource Port" );
			String resourceName = jo.getString( "Name" );
			String resourceDescription = jo.getString( "Description" );
			myKey = new RelaySigner();
			myKey.readPrivateKeyFromJSON( jo.getJSONObject( "My Key" ) );

			resourceAcceptData = new RelayResourceAcceptData( myKey, resourceName, resourceDescription );
			resourceAcceptData.setLog( log );
			resourceAcceptData.setPrintD5( jo.getBoolean( "Transport Log" ) );
			resourceAcceptData.setOnClosed( this::onClosed );
			resourceAcceptData.connect( host, resourcePort, 3 );
			}
		catch( Throwable ex )
		{
			log.writeln( Colors.RED_I, ex.toString() );
		}
	}

	// -------------------------------------------------------------------------------------------------------------
	private void onClosed()
	{
		log.writeln( Colors.RED_I, "Connection with Relay closed" );
	}

	// =================================================================================================================
	class RelayResourceAcceptData extends RelayResourceClient
	{
		long acceptedDataSize = 0;

		// -------------------------------------------------------------------------------------------------------------
		public RelayResourceAcceptData( RelaySigner resourceKey, String name, String description )
		{
			super( resourceKey, name, description, 4, "AcceptData" );
			setCommandDataLimit( 100_000_000 );
		}

		// -------------------------------------------------------------------------------------------------------------
		@Override
		protected Binary dispatchSend( long userHandle, int userToResourceIndex, int commandCode, Binary data )
		{
			MUST( data.size() > 0, "Error: No data sent" );
			acceptedDataSize += data.size();
			AcceptData.this.log.writeln( "Принято: " + data.size() + ".  Всего: " + acceptedDataSize );

			return data.first( 1 ); // Отправляем обратно первый байт данных
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new AcceptData();
	}

}

