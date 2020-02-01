// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.log;

import java.io.FileWriter;
import java.io.IOException;

import org.denom.*;

import static org.denom.Ex.THROW;

/**
 * Файловый лог.
 */
public class LogFile implements ILog
{
	private FileWriter f;
	private ILog mNextLog;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать файловый лог.
	 * @param fileName - Имя файла.
	 * @param append - true - файл открывается для дозаписи, false - новый файл.
	 */
	public LogFile( String fileName, boolean append )
	{
		try
		{
			f = new FileWriter( fileName, append );
		}
		catch( IOException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void writeImpl( String text )
	{
		try
		{
			f.write( text );
			f.flush();
		}
		catch( IOException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void write( String text )
	{
		writeImpl( text );
		if( mNextLog != null )
		{
			mNextLog.write( text );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void write( int color, String text )
	{
		writeImpl( text );
		if( mNextLog != null )
		{
			mNextLog.write( color, text );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void writeln( String text )
	{
		write( text + Strings.ln );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void writeln( int color, String text )
	{
		write( color, text + Strings.ln );
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
		try
		{
			f.flush();
			f.close();
		}
		catch( IOException ex )
		{
			THROW( ex.toString() );
		}
	}

	// ---------------------------------------------------------------------------------------------
	@Override
	protected void finalize()
	{
		close();
	}

}
