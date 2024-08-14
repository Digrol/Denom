// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.Binary;
import org.denom.log.ILog;

import static org.denom.Ex.MUST;

/**
 * Декоратор для CardReader.
 * Переопределяет поведение методов Cmd().
 * Добавляет в cla каждого CApdu заданный номер логического канала и передаёт команду в реальный ридер на выполнение.
 * Метод transmit() не меняет cla, просто перенаправляет.
 * Все остальные методы перенаправляются в actualReader без изменений.
 */
public class CardReaderChannel extends CardReader
{
	private final CardReader actualReader;
	private final int logicalChannel;

	// -----------------------------------------------------------------------------------------------------------------
	public CardReaderChannel( CardReader actualReader, int logicalChannel )
	{
		MUST( actualReader != null, "null, No Reader" );
		this.actualReader = actualReader;
		this.logicalChannel = logicalChannel;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Номер логического канала.
	 */
	public int getChannelNumber()
	{
		return logicalChannel;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Ссылка на реальный ридер.
	 */
	CardReader getActualReader()
	{
		return actualReader;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public final RApdu Cmd( ISM sm, CApdu capdu, int expectedStatus )
	{
		this.rapdu = actualReader.Cmd( sm, capdu.addLogicalChannel( logicalChannel ), expectedStatus ).clone();
		this.resp = rapdu.response;
		this.cmdTime = actualReader.cmdTime;
		this.sumTime += cmdTime;
		return this.rapdu;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public RApdu transmit( CApdu capdu )
	{
		return actualReader.transmit( capdu );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public CardReaderChannel getCardChannel( int logicalChannel )
	{
		return new CardReaderChannel( this.actualReader, logicalChannel );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать лог для логирования транспортного уровня.
	 * null или LogDummy - не логировать.
	 */
	public CardReaderChannel setTransportLog( ILog log )
	{
		actualReader.setTransportLog( log );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ILog getTransportLog()
	{
		return actualReader.getTransportLog();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public CardReaderChannel setApduLogger( IApduLogger logger )
	{
		actualReader.setApduLogger( logger );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public IApduLogger getApduLogger()
	{
		return actualReader.getApduLogger();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary powerOn()
	{
		atr = actualReader.powerOn();
		return atr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Снять питание с карты.
	 */
	public void powerOff()
	{
		actualReader.powerOff();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * powerOff и powerOn
	 * @return - ответ карты (ATR).
	 */
	public Binary reset()
	{
		atr = actualReader.reset();
		return atr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String[] enumReaders()
	{
		return actualReader.enumReaders();
	}

	@Override
	public CardReader connect( String readerName )
	{
		return actualReader.connect( readerName );
	}

	@Override
	public void disconnect()
	{
		actualReader.disconnect();
	}

	@Override
	public String getName()
	{
		return actualReader.getName();
	}

	@Override
	public boolean isCardPresent()
	{
		return actualReader.isCardPresent();
	}

	@Override
	public boolean waitCardPresent( int timeoutSec )
	{
		return actualReader.waitCardPresent( timeoutSec );
	}

	@Override
	public boolean waitCardRemove( int timeoutSec )
	{
		return actualReader.waitCardRemove( timeoutSec );
	}

	@Override
	protected Binary powerOnImpl()
	{
		return actualReader.powerOnImpl();
	}

	@Override
	protected void powerOffImpl()
	{
		actualReader.powerOffImpl();
	}

	@Override
	protected Binary resetImpl()
	{
		return actualReader.resetImpl();
	}

	@Override
	public void close()
	{
		actualReader.close();
	}
}
