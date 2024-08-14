// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.*;
import org.denom.log.ILog;

public class ApduLoggerDummy implements IApduLogger
{
	ILog log;
	@Override
	public void setLog( ILog log ) { this.log = log; }
	@Override
	public ILog getLog(){ return log; }
	@Override
	public void printPowerOn() {}
	@Override
	public void printPowerOff() {}
	@Override
	public void printReset() {}
	@Override
	public void printATR( Binary atr ) {}
	@Override
	public void printBeforeCommand( CApdu capdu, String callClassName ) {}
	@Override
	public void printCApduSM( CApdu capduSM ) {}
	@Override
	public void printRApduSM( RApdu rapduSM, boolean isTlvData ) {}
	@Override
	public void printAfterCommand( RApdu rapdu, long commandTime, boolean isTlvData ) {}
}
