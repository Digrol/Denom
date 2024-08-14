// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.*;
import org.denom.log.Colors;
import org.denom.log.ILog;

public class ApduLoggerMinimal implements IApduLogger
{
	private ILog log;
	private boolean isPrintCallPlace = false;
	private boolean isPrintCommandTime = false;
	private boolean isPrintDescription = false;

	// -----------------------------------------------------------------------------------------------------------------
	public ApduLoggerMinimal( ILog log )
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
	public ApduLoggerMinimal setPrintCallPlace( boolean isPrintCallPlace )
	{
		this.isPrintCallPlace = isPrintCallPlace;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ApduLoggerMinimal setPrintDescription( boolean isPrintDescription )
	{
		this.isPrintDescription = isPrintDescription;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ApduLoggerMinimal setPrintCommandTime( boolean isPrintCommandTime )
	{
		this.isPrintCommandTime = isPrintCommandTime;
		return this;
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
	private String oneLineCApdu( CApdu capdu )
	{
		Binary b = capdu.toBin();
		
		StringBuilder sb = new StringBuilder();
		sb.append( " ->  " );
		sb.append( b.first( 4 ).Hex( 1 ) );
		
		if( b.size() > 4 )
		{
			sb.append( "  " );
			sb.append( b.slice( 4, 1 ).Hex() );
		}
		if( b.size() > 5 )
		{
			sb.append( "  " );
			int restLen = b.size() - 5;
			if( restLen > 0 && (capdu.getNe() > 0) )
			{
				sb.append( b.slice( 5, b.size() - 6 ).Hex() );
				sb.append( "  " );
				sb.append( b.last( 1 ).Hex() );
			}
			else
			{
				sb.append( b.slice( 5, b.size() - 5 ).Hex() );

			}
		}
		return sb.toString();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private String oneLineRApdu( RApdu rapdu )
	{
		String s = " <-  ";
		if( !rapdu.response.empty() )
		{
			s += rapdu.response.Hex();
			s += "  ";
		}
		s += Binary.Num_Bin( rapdu.status, 2 ).Hex();
		return s;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printBeforeCommand( CApdu capdu, String callClassName )
	{
		log.writeln( "" );

		if( isPrintCallPlace )
		{
			log.write( Colors.DARK_GRAY, Strings.currentDateTime() + " -- " );
			log.writeln( Colors.DARK_GRAY, Ex.getCallerPlace( callClassName ) );
		}
		if( isPrintDescription && (capdu.description != null) && !capdu.description.isEmpty() )
			log.writeln( 0xFFA0A0EE, capdu.description );

		log.writeln( 0xFF60DADA, oneLineCApdu( capdu ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printCApduSM( CApdu capduSM )
	{
		log.writeln( Colors.DARK_GRAY, "\t" + oneLineCApdu( capduSM ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printRApduSM( RApdu rapduSM, boolean isTlvData )
	{
		log.writeln( Colors.DARK_GRAY, "\t" + oneLineRApdu( rapduSM ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void printAfterCommand( RApdu rapdu, long commandTime, boolean isTlvData )
	{
		int color = rapdu.isOk() ? 0xFF70DA70 : Colors.YELLOW_I;
		log.writeln( color, oneLineRApdu( rapdu ) );
		if( isPrintCommandTime )
			log.writeln( Colors.DARK_GRAY, "cmd time: " + commandTime + " ms" );
	}

}
