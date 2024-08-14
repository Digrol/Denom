// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.log;

import org.denom.Strings;

/**
 * Лог - стандартный поток вывода - System.out. Цвет добавляется Escape-кодами.
 */
public class LogConsoleANSI implements ILog
{
	private ILog mNextLog;

	public static final String COLOR_RESET = "\033[0m";

	// -----------------------------------------------------------------------------------------------------------------
	public static String toEscColor( int color )
	{
		switch( color )
		{
			case Colors.BLACK:        return "\033[30m";
			case Colors.RED:          return "\033[31m";
			case Colors.GREEN:        return "\033[32m";
			case Colors.YELLOW:       return "\033[33m";
			case Colors.BLUE:         return "\033[34m";
			case Colors.MAGENTA:      return "\033[35m";
			case Colors.CYAN:         return "\033[36m";
			case Colors.GRAY:         return "\033[37m";
			case Colors.DARK_GRAY:    return "\033[90m";
			case Colors.RED_I:        return "\033[91m";
			case Colors.GREEN_I:      return "\033[92m";
			case Colors.YELLOW_I:     return "\033[93m";
			case Colors.BLUE_I:       return "\033[94m";
			case Colors.MAGENTA_I:    return "\033[95m";
			case Colors.CYAN_I:       return "\033[96m";
			case Colors.WHITE:        return "\033[97m";
			default: return "";
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public LogConsoleANSI() {}

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
		System.out.print( toEscColor( color ) );
		System.out.print( text );
		System.out.print( COLOR_RESET );
		
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
