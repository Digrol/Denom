// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.net.*;

import static org.denom.Ex.*;

// -----------------------------------------------------------------------------------------------------------------
public class D5ResponseServerSession extends TCPServerSession
{
	protected final int bufSize;

	protected final ILog log;
	protected final D5ResponseDispatcher dispatcher;

	private ByteBuffer[] inBufs;

	protected long lastActivity;
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * For creating instances by method newInstance.
	 */
	public D5ResponseServerSession( int bufSize, ILog log, D5ResponseDispatcher dispatcher )
	{
		super();
		this.bufSize = bufSize;
		this.log = log;
		this.dispatcher = dispatcher;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public D5ResponseServerSession newInstance( TCPServer tcpServer, SocketChannel clientSocket )
	{
		return new D5ResponseServerSession( bufSize, log, dispatcher, tcpServer, clientSocket );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected D5ResponseServerSession( int bufSize, ILog log, D5ResponseDispatcher commandDispatcher,
			TCPServer tcpServer, SocketChannel clientSocket )
	{
		super( tcpServer, clientSocket );
		this.bufSize = bufSize;
		this.log = log;
		this.dispatcher = commandDispatcher;
		this.lastActivity = System.nanoTime();

		inBufs = new ByteBuffer[ 2 ];
		inBufs[ 0 ] = ByteBuffer.allocate( 16 );
		inBufs[ 1 ] = ByteBuffer.allocate( bufSize );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public void sendCommand( int commandCode, final Binary commandData )
	{
		D5Command command = new D5Command();
		command.index = 1;
		command.code = commandCode;
		command.data = commandData;

		Binary vrcuBin = new Binary();
		command.encode( vrcuBin );
		ByteBuffer buf = ByteBuffer.wrap( vrcuBin.getDataRef() );
		buf.limit( vrcuBin.size() );

		writeToSocket( buf );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
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

			// Is D5Response Header recieved completely
			if( headerBuf.remaining() != 0 )
				return;

			int dataLen = headerBuf.getInt( 12 );
			MUST( (dataLen >= 0) && (dataLen <= bufSize), "Too large D5Response" );

			if( dataBuf.position() < dataLen )
				return;

			MUST( dataBuf.position() == dataLen, "Wrong Length in D5Response" );

			// D5Response recieved completely
			D5Response response = new D5Response();
			response.index = headerBuf.getInt( 0 );
			response.code = headerBuf.getInt( 4 );
			response.status = headerBuf.getInt( 8 );
			response.data.assign( dataBuf.array(), 0, dataLen );

			headerBuf.clear();
			dataBuf.clear();

			lastActivity = System.nanoTime();

			dispatcher.process( this, response );
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
	
}