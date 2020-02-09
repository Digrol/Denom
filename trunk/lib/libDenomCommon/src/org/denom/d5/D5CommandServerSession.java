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
public class D5CommandServerSession extends TCPServerSession
{
	protected final int bufSize;

	protected final ILog log;
	protected final D5CommandDispatcher dispatcher;

	private ByteBuffer[] inBufs;

	protected int commandsNumber;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * For creating object instances by method newInstance.
	 */
	public D5CommandServerSession( int bufSize, ILog log, D5CommandDispatcher dispatcher )
	{
		super();
		this.bufSize = bufSize;
		this.log = log;
		this.dispatcher = dispatcher;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public D5CommandServerSession newInstance( TCPServer tcpProcessor, SocketChannel clientSocket )
	{
		return new D5CommandServerSession( bufSize, log, dispatcher, tcpProcessor, clientSocket );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected D5CommandServerSession( int bufSize, ILog log, D5CommandDispatcher commandDispatcher,
			TCPServer tcpProcessor, SocketChannel clientSocket )
	{
		super( tcpProcessor, clientSocket );
		this.bufSize = bufSize;
		this.log = log;
		this.dispatcher = commandDispatcher;

		inBufs = new ByteBuffer[ 2 ];
		inBufs[ 0 ] = ByteBuffer.allocate( 12 );
		inBufs[ 1 ] = ByteBuffer.allocate( bufSize );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void readFromSocket()
	{
		try
		{
			long readBytes = socket.read( inBufs );
			if( readBytes <= 0 )
			{
				close();
				return;
			}

			ByteBuffer headerBuf = inBufs[ 0 ];
			ByteBuffer dataBuf = inBufs[ 1 ];

			if( headerBuf.remaining() != 0 ) // Is header fully accepted?
				return;

			int dataLen = headerBuf.getInt( 8 );
			MUST( (dataLen >= 0) && (dataLen <= bufSize), "Too large D5Command from client" );

			if( dataBuf.position() < dataLen )
				return;

			MUST( dataBuf.position() == dataLen, "Wrong Len in D5Command" );

			// Command is fully accepted
			D5Command command = new D5Command();
			command.index = headerBuf.getInt( 0 );
			command.code  = headerBuf.getInt( 4 );
			command.data.assign( dataBuf.array(), 0, dataLen );

			headerBuf.clear();
			dataBuf.clear();

			commandsNumber++;
			dispatcher.process( this, command );
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
	public void sendResponse( D5Response response )
	{
		Binary bin = new Binary();
		response.encode( bin );
		ByteBuffer buf = ByteBuffer.wrap( bin.getDataRef() );
		buf.limit( bin.size() );

		super.writeToSocket( buf );
	}

}