// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.relay;

import org.denom.format.*;

public class DenomRelayOptions
{
	/**
	 * Server Hostname.
	 */
	String host = "";

	int userPort = 4210;
	int userDispatcherThreads = 8;
	int userSessionBufSize = 10_000_000;
	int userDispatcherThreadStackSize = 100000;

	boolean fileLog = false;
	boolean showTransport = false;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Serialize options to JSON-object.
	 */
	public JSONObject toJSON()
	{
		JSONObject jo = new JSONObject();

		jo.put( "Host", host );

		jo.put( "User Port", userPort );
		jo.put( "User Dispatcher Threads", userDispatcherThreads );
		jo.put( "User Session BufSize", userSessionBufSize );
		jo.put( "User Dispatcher thread stack size", userDispatcherThreadStackSize );

		jo.put( "File log", fileLog );
		jo.put( "Show transport", showTransport );

		return jo;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Read Options from JSON-object.
	 * @return this.
	 */
	DenomRelayOptions fromJSON( JSONObject jo )
	{
		host = jo.getString( "Host" );

		userPort = jo.getInt( "User Port" );
		userDispatcherThreads = jo.getInt( "User Dispatcher Threads" );
		userSessionBufSize = jo.getInt( "User Session BufSize" );
		userDispatcherThreadStackSize = jo.getInt( "User Dispatcher thread stack size" );

		fileLog = jo.getBoolean( "File log" );
		showTransport = jo.getBoolean( "Show transport" );

		return this;
	}

}
