// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5;

import java.net.Socket;
import java.net.SocketException;

import org.denom.*;
import org.denom.log.*;
import org.denom.net.SocketClient;

import static org.denom.Binary.Bin;
import static org.denom.Ex.*;


// ----------------------------------------------------------------------------------------------------------------
/**
 * Client, that listens D5 Commands from server and sends D5 Responds according to 'D5 Protocol'.
 */
public abstract class D5ReverseClient extends Thread implements AutoCloseable
{
	private SocketClient socketClient = null;

	/**
	 * Limit for data size accepted from server.
	 */
	private int commandDataLimit = 100_000_000;

	/**
	 * In-out buffer.
	 */
	private Binary buf = new Binary().reserve( 512 );

	protected ILog log = new LogDummy();

	boolean printCommands = false;

	// -----------------------------------------------------------------------------------------------------------------
	public D5ReverseClient() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Set log for writing Errors, printing Commands and Responses. Can be 'null'.
	 */
	public D5ReverseClient setLog( ILog log )
	{
		this.log = log;
		return this;
	}

	public void setPrintCommands( boolean isPrintCommands )
	{
		this.printCommands = isPrintCommands;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public D5ReverseClient connect( String host, int port, int connectTimeoutSec )
	{
		SocketClient socket = new SocketClient( connectTimeoutSec );
		socket.connectHard( host, port );
		this.socketClient = socket;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Can be 'null', then method close() will do nothing.
	 */
	public D5ReverseClient setSocketClient( SocketClient socketClient )
	{
		this.socketClient = socketClient;
		return this;
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
	public void setCommandDataLimit( int newLimit )
	{
		this.commandDataLimit = newLimit;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void run()
	{
		Socket socket = socketClient.getSocket();

		try
		{
			setReadTimeoutSec( 0 );

			while( !socket.isClosed() )
			{
				buf.clear();

				// Read D5 Command header (12 bytes)
				socketClient.read( buf, 12 );

				// Read Command data
				int dataSize = buf.getIntBE( 8 );
				MUST( (dataSize >= 0) && (dataSize <= commandDataLimit), "Too large D5 Command from server" );
				socketClient.read( buf, dataSize );

				// D5 Command recieved
				if( printCommands && (log != null) && !(log instanceof LogDummy) )
				{
					log.writeln( "D5 Command : " + buf.Hex( 4, 0, 0, 0 ) );
				}

				processCommand( buf );
			}
		}
		catch( Throwable ex )
		{
			if( !Thread.interrupted() && (log != null) && !(log instanceof LogDummy) )
			{
				log.writeln( Colors.YELLOW_I, ex.toString() );
			}
		}
		finally
		{
			socketClient.close();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void processCommand( final Binary commandBuf )
	{
		int commandIndex = commandBuf.getIntBE( 0 );
		int commandCode = commandBuf.getIntBE( 4 );
		int dataLen = commandBuf.getIntBE( 8 );

		Binary responseData = Bin();
		int status = D5Response.STATUS_OK;

		try
		{
			commandBuf.assign( commandBuf, 12, dataLen );
			responseData = dispatch( commandCode, commandBuf );
		}
		catch( Ex ex )
		{
			status = D5Response.STATUS_UNKNOWN_ERROR;
			if( (ex.code & 0xE0000000) == 0xE0000000 )
			{
				status = ex.code;
			}
			responseData.fromUTF8( ex.getMessage() );
		}
		catch( Throwable ex )
		{
			status = D5Response.STATUS_UNKNOWN_ERROR;
			responseData.fromUTF8( ex.toString() );
		}

		if( responseData != null )
		{
			D5Response response = new D5Response();
			response.code   = commandCode - 0x20000000;
			response.status = status;
			response.index  = commandIndex;
			response.data   = responseData;
			sendD5Response( response );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected abstract Binary dispatch( int commandCode, Binary commandBuf );

	// -----------------------------------------------------------------------------------------------------------------
	public void sendD5Response( D5Response response )
	{
		Binary bin = new Binary();
		response.encode( bin );

		if( printCommands && (log != null) && !(log instanceof LogDummy) )
		{
			log.writeln( "D5 Response: " + bin.Hex( 4, 0, 0, 0 ) );
		}
		socketClient.write( bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void close()
	{
		// Останавливаем поток через interrupt.
		this.interrupt();
		while( this.isAlive() )
		{
			Sys.sleep( 10 );
		}
		socketClient.close();
	}

}