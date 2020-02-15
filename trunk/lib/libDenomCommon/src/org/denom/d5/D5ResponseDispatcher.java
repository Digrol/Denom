// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5;

import java.util.concurrent.*;
import org.denom.*;

import static org.denom.Ex.*;


public abstract class D5ResponseDispatcher
{
	protected Arr<D5ResponseServerSession> sessions = new Arr<>();
	protected ExecutorService executor;

	// -----------------------------------------------------------------------------------------------------------------
	public D5ResponseDispatcher( int threadsNumber )
	{
		executor = Executors.newFixedThreadPool( threadsNumber,
			new ThreadFactoryNamed( this.getClass().getSimpleName(), Thread.NORM_PRIORITY, 0 ) );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	protected abstract void dispatch( D5ResponseServerSession session, D5Response response );
	
	// -----------------------------------------------------------------------------------------------------------------
	public void process( D5ResponseServerSession session, D5Response response )
	{
		dispatch( session, response );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public void close()
	{
		for( D5ResponseServerSession session : sessions )
		{
			session.close();
		}
		
		executor.shutdownNow();
		try
		{
			MUST( executor.awaitTermination( 3, TimeUnit.SECONDS ), "Can't stop " + this.getClass().getSimpleName() );
		}
		catch( InterruptedException ex ) {}
	}
}
