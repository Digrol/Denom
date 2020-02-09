// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5;

import java.util.concurrent.*;
import org.denom.*;

import static org.denom.Ex.MUST;

// ----------------------------------------------------------------------------------------------------------------
public abstract class D5CommandDispatcher
{
	private final ExecutorService executor;

	// -----------------------------------------------------------------------------------------------------------------
	public D5CommandDispatcher( int threadsNumber )
	{
		executor = Executors.newFixedThreadPool( threadsNumber,
				new ThreadFactoryNamed( this.getClass().getSimpleName(), Thread.NORM_PRIORITY, 0 ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected abstract Binary dispatch( D5CommandServerSession session, D5Command command );

	// -----------------------------------------------------------------------------------------------------------------
	protected void processImpl( D5CommandServerSession session, D5Command command )
	{
		D5Response response = new D5Response();
		response.code   = command.code - 0x20000000;
		response.status = D5Response.STATUS_OK;
		response.index  = command.index;

		try
		{
			response.data = dispatch( session, command );
		}
		catch( Ex ex )
		{
			response.status = D5Response.STATUS_UNKNOWN_ERROR;
			if( (ex.code & 0xE0000000) == 0xE0000000 )
			{
				response.status = ex.code;
			}
			response.data.fromUTF8( ex.getMessage() );
		}
		catch( Throwable ex )
		{
			response.status = D5Response.STATUS_UNKNOWN_ERROR;
			response.data.fromUTF8( ex.toString() );
		}

		session.sendResponse( response );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void process( D5CommandServerSession session, D5Command command )
	{
		executor.execute( () -> processImpl( session, command ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void close()
	{
		executor.shutdownNow();
		try
		{
			MUST( executor.awaitTermination( 3, TimeUnit.SECONDS ), "Can't stop " + this.getClass().getSimpleName() );
		}
		catch( InterruptedException ex ) {}
	}

}