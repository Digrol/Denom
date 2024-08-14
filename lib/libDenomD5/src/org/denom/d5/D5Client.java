// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5;

import java.net.SocketException;

import org.denom.*;
import org.denom.log.*;
import org.denom.net.SocketClient;

import static org.denom.Ex.*;


// ----------------------------------------------------------------------------------------------------------------
/**
 * Client, that sends commands to server according to 'D5 Protocol'.
 */
public class D5Client implements AutoCloseable
{
	/**
	 * Ограничение на размер принимаемых от сервера ответов по умолчанию.
	 */
	private static final int DEFAULT_RESPONSE_DATA_LIMIT = 100_000_000;

	/**
	 * Client socket for sending D5 Commands and accepting D5 Responses.
	 */
	private SocketClient socketClient = null;

	/**
	 * Limit for data size accepted from server.
	 */
	private int responseDataLimit = DEFAULT_RESPONSE_DATA_LIMIT;

	/**
	 * Буфер для приёмо-передачи данных.
	 */
	private Binary buf = new Binary().reserve( 512 );

	private int commandIndex = 0;

	/**
	 * Optimization - to not create this objects on every command.
	 */
	protected D5Command  curCommand  = new D5Command();
	protected D5Response curResponse = new D5Response();

	protected ILog log = null;

	// -----------------------------------------------------------------------------------------------------------------
	public D5Client() {}

	// -----------------------------------------------------------------------------------------------------------------
	public D5Client( SocketClient socketClient )
	{
		this.socketClient = socketClient;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public D5Client( String host, int port )
	{
		this( host, port, 10 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public D5Client( String host, int port, int connectTimeoutSec )
	{
		SocketClient socket = new SocketClient( connectTimeoutSec );
		socket.connectHard( host, port );
		this.socketClient = socket;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Set log for printing Commands and Responses. Can be 'null'.
	 */
	public D5Client setLog( ILog log )
	{
		this.log = log;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/***
	 * Can be 'null', then method close() will do nothing.
	 */
	public void setSocketClient( SocketClient socketClient )
	{
		this.socketClient = socketClient;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public SocketClient getSocketClient()
	{
		return socketClient;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public void setReadTimeoutSec( int sec )
	{
		MUST( socketClient != null, "Null SocketClient" );

		try
		{
			socketClient.getSocket().setSoTimeout( sec * 1000 );
		}
		catch( SocketException ex )
		{
			throw new Ex( ex.toString() );
		}
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public int getReadTimeoutSec()
	{
		MUST( socketClient != null, "Null SocketClient" );

		try
		{
			return socketClient.getSocket().getSoTimeout() / 1000;
		}
		catch( SocketException ex )
		{
			throw new Ex( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Set new data limit for server responses.
	 */
	public void setResponseDataLimit( int newLimit )
	{
		this.responseDataLimit = newLimit;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Передача буфера с VRCU и получение ответного VRAU в этот же буфер.
	 * Можно перекрывать в потомках.
	 */
	protected void transmit( Binary buf )
	{
		MUST( socketClient != null, "socketClient not set for D5Client" );

		if( (log != null) && !(log instanceof LogDummy) )
		{
			log.writeln( "D5 Command : " + buf.Hex( 4, 0, 0, 0 ) );
		}

		socketClient.write( buf );

		buf.clear();

		socketClient.read( buf, 16 );
		int respSize = buf.getIntBE( 12 );
		MUST( respSize >= 0, "Negative D5Response data size" );
		MUST( respSize <= responseDataLimit, "D5Response from server exceeds client limit" );

		socketClient.read( buf, respSize );
		
		if( (log != null) && !(log instanceof LogDummy) )
		{
			log.writeln( "D5 Response: " + buf.Hex( 4, 0, 0, 0 ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Send D5Command and recieve D5Response.
	 */
	public void command( final D5Command cmd, D5Response response )
	{
		cmd.encode( buf );
		transmit( buf );

		MUST( response.decode( buf ), "Wrong D5Response syntax" );

		if( response.status != response.STATUS_OK )
		{
			THROW( response.status, String.format( "(0x%08X) %s", response.status, response.data.asUTF8() ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * D5Command.index kept in class and increments on every command.
	 * @return reference to D5Response kept in this object. NOT COPY.
	 */
	public D5Response command( int commandCode, final Binary commandData )
	{
		++commandIndex;
		curCommand.index = commandIndex;
		curCommand.code = commandCode;
		curCommand.data = commandData;
		command( curCommand, curResponse );
		return curResponse;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Send D5Command - get list of supported D5Commands from server.
	 */
	public Arr<Integer> commandEnumCommands()
	{
		Arr<Integer> arr = new Arr<Integer>();

		command( D5Command.ENUM_COMMANDS, new Binary() );

		for( int offset = 0; offset < curResponse.data.size(); offset +=4 )
		{
			arr.add( curResponse.data.getIntBE( offset ) );
		}
		return arr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Send command - Execute Token.
	 * What means 'token', depends of logic level.
	 * For example, it can stop server, if 'token' valid.
	 */
	public void commandExecuteToken( final Binary token )
	{
		command( D5Command.EXECUTE_TOKEN, token );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void close()
	{
		if( socketClient != null )
			socketClient.close();
	}

}