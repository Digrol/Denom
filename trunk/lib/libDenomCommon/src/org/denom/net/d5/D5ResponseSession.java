// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.denom.*;
import org.denom.log.*;
import org.denom.net.*;

import static org.denom.Ex.*;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Responsible for parsing bytes in channel into D5Response structure.
 */
public abstract class D5ResponseSession extends TCPServerSession
{
	protected final int bufSize;
	public final ILog log;

	private ByteBuffer headerBuf;
	private Binary dataBin = null;
	private ByteBuffer dataBuf = null;
	private final AtomicInteger index = new AtomicInteger( 1 );

	public long lastActivity;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * For creating instances by method newInstance.
	 */
	public D5ResponseSession( int bufSize, ILog log )
	{
		super();
		this.bufSize = bufSize;
		this.log = log;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected D5ResponseSession( int bufSize, ILog log, TCPServer tcpServer, SocketChannel clientSocket )
	{
		super( tcpServer, clientSocket );
		this.bufSize = bufSize;
		this.log = log;

		this.lastActivity = System.nanoTime();

		headerBuf = ByteBuffer.allocate( 16 );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public void sendCommand( int commandCode, final Binary commandData )
	{
		Binary bin = new Binary().reserve( commandData.size() + 12 );
		bin.addInt( index.getAndIncrement() );
		bin.addInt( commandCode );
		bin.addInt( commandData.size() );
		bin.add( commandData );

		ByteBuffer buf = ByteBuffer.wrap( bin.getDataRef(), 0, bin.size() );
		writeToSocket( buf );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void sendCommand( D5Command command )
	{
		command.index = index.getAndIncrement();

		Binary bin = new Binary();
		command.encode( bin );
		ByteBuffer buf = ByteBuffer.wrap( bin.getDataRef(), 0, bin.size() );

		writeToSocket( buf );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * IO Thread.
	 */
	public void readFromSocket()
	{
		try
		{
			lastActivity = System.nanoTime();

			// Waiting D5 header
			if( headerBuf.remaining() != 0 )
			{
				long readBytes = socket.read( headerBuf );
				if( readBytes <= 0 )
				{
					close();
					return;
				}

				if( headerBuf.remaining() != 0 )
					return;
			}

			// Got D5 header
			int dataLen = headerBuf.getInt( 12 );
			if( dataBuf == null )
			{
				MUST( (dataLen >= 0) && (dataLen <= bufSize), "Too large D5Response" );
				dataBin = new Binary( dataLen );
				dataBuf = ByteBuffer.wrap( dataBin.getDataRef() );
			}

			long readBytes = socket.read( dataBuf );
			if( readBytes < 0 )
			{
				close();
				return;
			}

			// Wait next data part
			if( dataBuf.remaining() != 0 )
				return;

			// D5Response recieved completely
			D5Response response = new D5Response();
			response.index = headerBuf.getInt( 0 );
			response.code = headerBuf.getInt( 4 );
			response.status = headerBuf.getInt( 8 );
			response.data = dataBin;

			headerBuf.clear();
			dataBin = null;
			dataBuf = null;

			processResponse( response );
		}
		catch( IOException ex )
		{
			close();
		}
		catch( Ex ex )
		{
			log.writeln( Colors.RED_I, ex.toString() );
			close();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Called in IO Thread.
	 * Do all work in other threads.
	 */
	protected abstract void processResponse( D5Response response );

}