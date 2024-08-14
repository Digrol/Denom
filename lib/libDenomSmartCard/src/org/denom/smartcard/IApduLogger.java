// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.*;
import org.denom.log.ILog;

/**
 * Интерфейс для классов, выводящих в лог APDU-обмен с картой.
 */
public interface IApduLogger
{
	public void setLog( ILog log );
	public ILog getLog();
	public void printPowerOn();
	public void printPowerOff();
	public void printReset();
	public void printATR( Binary atr );
	public void printBeforeCommand( CApdu capdu, String callClassName );
	public void printCApduSM( CApdu capduSM );
	public void printRApduSM( RApdu rapduSM, boolean isTlvData );
	public void printAfterCommand( RApdu rapdu, long commandTime, boolean isTlvData );
}
