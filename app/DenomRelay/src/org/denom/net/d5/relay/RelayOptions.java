// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5.relay;

import org.denom.d5.relay.RelaySigner;
import org.denom.format.*;

public class RelayOptions
{
	boolean fileLog = false;
	boolean showTransport = false;

	String host;

	int workerThreads;
	int sessionBufSize = 10_000_000;
	
	int userPort;

	public final static class ResourceOptions
	{
		// Порт, по которому подключаются ресурсы 
		int port;
		// Таймаут в секундах - сколько Relay ждёт ответ от ресурса.
		// Если ресурс не уложится в отведенное время, то Relay закроет с ним соединение.
		int timeoutSec;
		// Максимальная длина строки с именем Ресурса
		int nameMaxLen;
		// Максимальная длина строки с описанием Ресурса
		int descriptionMaxLen;
	}
	ResourceOptions resource = new ResourceOptions();

	RelaySigner relayKey = new RelaySigner();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Read Options from JSON-object.
	 */
	void fromJSON( JSONObject jo )
	{
		fileLog = jo.getBoolean( "File log" ); // false
		showTransport = jo.getBoolean( "Show transport" ); // false

		host = jo.getString( "Host" ); // ""

		workerThreads = jo.getInt( "Worker Threads" ); // 8
		sessionBufSize = jo.getInt( "Session BufSize" );

		userPort = jo.getInt( "User Port" ); // 4210

		JSONObject joResource = jo.getJSONObject( "Resource" );
		resource.port = joResource.getInt( "Port" ); // 4211
		resource.timeoutSec = joResource.getInt( "Timeout Sec" ); // 5
		resource.nameMaxLen = joResource.getInt( "Name Max Length" ); // 256
		resource.descriptionMaxLen = joResource.getInt( "Description Max Length" );

		relayKey.readPrivateKeyFromJSON( jo.getJSONObject( "Relay Key" ) );
	}

}
