// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.log;

public class LogDummy implements ILog
{
	@Override
	public void write( String text ) {}

	@Override
	public void writeln( String text ) {}

	@Override
	public void write( int color, String text ) {}

	@Override
	public void writeln( int color, String text ) {}

	@Override
	public void setDefaultColor( int color ) {}

	@Override
	public ILog setNext( ILog log )
	{
		throw new RuntimeException( "LogDummy can't have next log" );
	}

	@Override
	public void close() {}
}
