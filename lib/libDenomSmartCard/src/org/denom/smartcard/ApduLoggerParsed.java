// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.*;
import org.denom.log.Colors;
import org.denom.log.ILog;

public class ApduLoggerParsed implements IApduLogger
{
	private ILog log;

	// -----------------------------------------------------------------------------------------------------------------
	public ApduLoggerParsed( ILog log )
	{
		this.log = log;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void setLog( ILog log )
	{
		this.log = log;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public ILog getLog()
	{
		return log;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printPowerOn()
	{
		log.writeln( Colors.CYAN_I, "Power on" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printPowerOff()
	{
		log.writeln( Colors.CYAN_I, "Power off" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printReset()
	{
		log.writeln( Colors.CYAN_I, "Reset" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printATR( Binary atr )
	{
		log.writeln( Colors.CYAN_I, "ATR: " + atr.Hex() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printBeforeCommand( CApdu capdu, String callClassName )
	{
		log.writeln( Colors.CYAN, "----------------------------------------------------------------" );
		log.write( Colors.YELLOW, Strings.currentDateTime() + " -- " );
		log.writeln( Colors.YELLOW, Ex.getCallerPlace( callClassName ) );
		capdu.print( log, Colors.GRAY, Colors.CYAN_I, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printCApduSM( CApdu capduSM )
	{
		log.writeln( Colors.DARK_GRAY, "    +++++++++++++++ Secure Messaging +++++++++++++++" );
		capduSM.print( log, Colors.DARK_GRAY, 0, 4 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printRApduSM( RApdu rapduSM, boolean isTlvData )
	{
		log.writeln( Colors.DARK_GRAY, "    ~~~~~~~~~~~~~" );
		rapduSM.print( log, Colors.DARK_GRAY, 4, isTlvData );
		log.writeln( Colors.DARK_GRAY, "    +++++++++++++++ Secure Messaging +++++++++++++++" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printAfterCommand( RApdu rapdu, long commandTime, boolean isTlvData )
	{
		log.writeln( Colors.GRAY, "-------------------------" );
		rapdu.print( log, 0xFFBeDeDe, 0, isTlvData );
		log.writeln( Colors.MAGENTA, "Command time: " + commandTime + " ms" );
		log.writeln( Colors.CYAN, "----------------------------------------------------------------" );
	}

}
