// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.log;

import org.denom.Strings;

/**
 * Лог - стандартный поток вывода - System.out. Цвет игнорируется.
 */
public class LogConsole implements ILog
{
	private ILog mNextLog;

	// -----------------------------------------------------------------------------------------------------------------
	public LogConsole() {}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void write( String text )
	{
		System.out.print( text );
		if( mNextLog != null )
		{
			mNextLog.write( text );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void write( int color, String text )
	{
		System.out.print( text );
		if( mNextLog != null )
		{
			mNextLog.write( color, text );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void writeln( String text )
	{
		this.write( text + Strings.ln );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void writeln( int color, String text )
	{
		this.write( color, text + Strings.ln );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void setDefaultColor( int color ) {}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public ILog setNext( ILog log )
	{
		mNextLog = log;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void close() {}

}
