// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.log;

import org.denom.*;

/**
 * Добавление в лог времени формирования записи (декорирует message).
 * При закрытии этого лога, закрывается лог, на который хранится ссылка.
 */
public class LogTime implements ILog
{
	private ILog mLog;
	private ILog mNextLog;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param log - этому объекту будет передан изменённый message.
	 */
	public LogTime( ILog log )
	{
		Ex.MUST( log != null, "параметр log должен != null" );
		mLog = log;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private String appendCurTime( String message )
	{
		return Strings.currentDateTime() + " -- " + message;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void write( String message )
	{
		if( !message.isEmpty() && !message.equals( Strings.ln ) )
		{
			message = appendCurTime( message );
		}
		mLog.write( message );
		if( mNextLog != null )
		{
			mNextLog.write( message );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void write( int color, String message )
	{
		if( !message.isEmpty() && !message.equals( Strings.ln ) )
		{
			message = appendCurTime( message );
		}
		mLog.write( color, message );
		if( mNextLog != null )
		{
			mNextLog.write( color, message );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void writeln( String message )
	{
		this.write( message + Strings.ln );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void writeln( int color, String message )
	{
		this.write( color, message + Strings.ln );
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
	public void close()
	{
		mLog.close();
	}
}
