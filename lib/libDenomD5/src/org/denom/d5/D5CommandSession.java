// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.net.*;

import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
public abstract class D5CommandSession extends TCPServerSession
{
	protected final int bufSize;
	protected final ILog log;

	private ByteBuffer headerBuf;
	private Binary dataBin = null;
	private ByteBuffer dataBuf = null;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Creates 'Session creator'.
	 * Sessions will be created later for each new connection by newInstance().
	 */
	public D5CommandSession( int bufSize, ILog log )
	{
		super();
		this.bufSize = bufSize;
		this.log = log;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected D5CommandSession( int bufSize, ILog log, TCPServer tcpProcessor, SocketChannel clientSocket )
	{
		super( tcpProcessor, clientSocket );
		this.bufSize = bufSize;
		this.log = log;

		headerBuf = ByteBuffer.allocate( 12 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Called in IO Thread.
	 * Read and parse data from socket till get full D5Command.
	 */
	@Override
	public void readFromSocket()
	{
		try
		{
			// Waiting D5Command Header
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

			// Got D5Command Header
			int dataLen = headerBuf.getInt( 8 );
			if( dataBuf == null )
			{
				MUST( (dataLen >= 0) && (dataLen <= bufSize), "Too large D5Command" );
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
			
			// D5Command recieved completely
			D5Command command = new D5Command();
			command.index = headerBuf.getInt( 0 );
			command.code = headerBuf.getInt( 4 );
			command.data = dataBin;

			headerBuf.clear();
			dataBin = null;
			dataBuf = null;

			processCommand( command );
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
	protected abstract void processCommand( D5Command command );

	// -----------------------------------------------------------------------------------------------------------------
	public void sendResponse( D5Response response )
	{
		Binary bin = new Binary();
		response.encode( bin );
		ByteBuffer buf = ByteBuffer.wrap( bin.getDataRef() );
		buf.limit( bin.size() );

		super.writeToSocket( buf );
	}

}