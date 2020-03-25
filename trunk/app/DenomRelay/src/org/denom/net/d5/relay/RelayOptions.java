// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5.relay;

import org.denom.format.*;

public class RelayOptions
{
	boolean fileLog = false;
	boolean showTransport = false;

	String host = "";

	int workerThreads = 8;
	int sessionBufSize = 10_000_000;
	
	int userPort = 4210;

	int resourcePort = 4211;
	int resourceTimeoutSec = 5;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Read Options from JSON-object.
	 */
	void fromJSON( JSONObject jo )
	{
		fileLog = jo.getBoolean( "File log" );
		showTransport = jo.getBoolean( "Show transport" );

		host = jo.getString( "Host" );

		workerThreads = jo.getInt( "Worker Threads" );
		sessionBufSize = jo.getInt( "Session BufSize" );

		userPort = jo.getInt( "User Port" );

		resourcePort = jo.getInt( "Resource Port" );
		resourceTimeoutSec = jo.getInt( "Resource Timeout Sec" );
	}

}
