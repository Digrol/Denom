// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom;

/**
 * Measure Time.
 */
public class Ticker
{
	long mStartTime;

	public Ticker()
	{
		restart();
	}

	public void restart()
	{
		mStartTime = System.nanoTime();
	}

	public long getDiff()
	{
		return System.nanoTime() - mStartTime;
	}

	public long getDiffMs()
	{
		return (System.nanoTime() - mStartTime) / 1000000;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static long measureMs( int numberOfIterations, Runnable f )
	{
		long startTime = System.nanoTime();
		for( ; numberOfIterations > 0; --numberOfIterations )
		{
			f.run();
		}
		return (System.nanoTime() - startTime) / 1000000; 
	}
}