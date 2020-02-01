// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

// -----------------------------------------------------------------------------------------------------------------
public class ThreadFactoryNamed implements ThreadFactory
{
	private final ThreadGroup group;
	private final AtomicInteger threadNumber = new AtomicInteger( 1 );
	private final String namePrefix;
	private final int stackSize;
	private final int priority;

	// -----------------------------------------------------------------------------------------------------------------
	public ThreadFactoryNamed( String groupName, int priority, int stackSize )
	{
		group = new ThreadGroup( groupName );
		namePrefix = groupName + "-";

		this.stackSize = stackSize;
		this.priority = priority;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Thread newThread( Runnable r )
	{
		Thread t = new Thread( group, r, namePrefix + threadNumber.getAndIncrement(), stackSize );
		t.setPriority( priority );
		return t;
	}
}
