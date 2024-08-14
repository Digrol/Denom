// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.*;
import org.denom.log.*;

/**
 * Abstract smart card reader (reader).
 * Descendants implement a specific transport to the reader, e.g. PC/SC, Socket, AndroidNFC.
 *
 * Example Usage:
 * CardReader cr = new CardReader***().setApduLog( apduLog );
 * cr.connect( "reader name" );
 * cr.powerOn();
 * cr.Cmd( myApduHelper(...) ); // Checks the status of command execution
 * cr.powerOff();
 * cr.close();
 * 
 * The 'transmit' method does NOT check the status of command execution by the card, it does not write to Apdu log.
 * Only using transport directly.
 */
public abstract class CardReader implements AutoCloseable
{
	/**
	 * Последнее полученное Response APDU.
	 */
	public RApdu rapdu = new RApdu();

	/**
	 * Ссылка на rapdu.response;
	 */
	public Binary resp = rapdu.response;

	/**
	 * Время выполнения последней команды в миллисекундах.
	 */
	public long cmdTime = 0;

	/**
	 * Суммарное время выполнения команд в миллисекундах.
	 * Можно обнулять снаружи, когда требуется замерять время части команд.
	 */
	public long sumTime = 0;

	/**
	 * Ответ карты на последнюю подачу питания или ресет.
	 * Заполняется в powerOn и reset.
	 */
	public Binary atr = new Binary();
	
	/**
	 * Имя класса в стеке, следующий за этим именем - тот, что нужно вывести как место вызова команды.
	 */
	public String callerClassName = null;
	
	// =================================================================================================================

	protected ILog transportLog = null;
	// Flag the presence of a log object, for optimization
	protected boolean isTransportLog;

	protected ISM sm = null;

	protected Ticker ticker = new Ticker();

	private final String thisClassName = CardReader.class.getName();
	protected IApduLogger apduLogger = new ApduLoggerDummy();

	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	protected CardReader() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Specify a log for transport layer logging.
	 * null or LogDummy - do not log.
	 */
	public CardReader setTransportLog( ILog log )
	{
		isTransportLog = (log != null) && !(log instanceof LogDummy);
		this.transportLog = log;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ILog getTransportLog()
	{
		return transportLog;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public CardReader setApduLogger( IApduLogger logger )
	{
		this.apduLogger = logger;
		if( apduLogger == null )
			apduLogger = new ApduLoggerDummy();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public IApduLogger getApduLogger()
	{
		return apduLogger;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает список имён ридеров.
	 * Имя используется при подключении к ридеру в {@link #connect(String)}
	 * @return список имён ридеров. 
	 */
	public abstract String[] enumReaders();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подключиться к ридеру по имени.
	 * @param readerName - Имя ридера.
	 * @return Ссылка на себя.
	 */
	public abstract CardReader connect( String readerName );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Отключиться от ридера.
	 */
	public abstract void disconnect();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить имя активного ридера.
	 * @return Имя активного ридера.
	 */
	public abstract String getName();

	// -----------------------------------------------------------------------------------------------------------------

	/**
	 * Проверить, есть ли карта в ридере.
	 */
	public abstract boolean isCardPresent();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Ожидать появления карты.
	 * @param timeoutSec - сколько времени ждать (в секундах), 0 - бесконечно.
	 * @return - true - карта уже есть или появилась в течение времени ожидания;
	 *    false - таймаут истёк, карты нет.
	 */
	public abstract boolean waitCardPresent( int timeoutSec );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Ожидать извлечения карты.
	 * @param timeoutSec - сколько времени ждать (в секундах), 0 - бесконечно.
	 * @return- true - карта отсутствует или извлечена в течение времени ожидания;
	 *    false - таймаут истёк, карта в ридере.
	 */
	public abstract boolean waitCardRemove( int timeoutSec );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return - ответ карты на подачу питания.
	 */
	protected abstract Binary powerOnImpl();

	protected abstract void powerOffImpl();

	protected abstract Binary resetImpl();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подать питание на карту.
	 * @return - ответ карты (ATR).
	 */
	public Binary powerOn()
	{
		apduLogger.printPowerOn();
		atr = powerOnImpl();
		apduLogger.printATR( atr );
		return atr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Снять питание с карты.
	 */
	public void powerOff()
	{
		apduLogger.printPowerOff();
		powerOffImpl();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * powerOff и powerOn
	 * @return - ответ карты (ATR).
	 */
	public Binary reset()
	{
		apduLogger.printReset();
		atr = resetImpl();
		apduLogger.printATR( atr );
		return atr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Отправить команду в карту.
	 * Статус выполнения команды НЕ анализируется.
	 * Каждый класс-наследник реализует этот транспортный метод по-своему.
	 * @param capdu - Командное APDU.
	 * @return Ответное APDU.
	 */
	public abstract RApdu transmit( CApdu capdu );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает декоратор для добавления номера логического канала в каждой CApdu.
	 * @param logicalChannel 0..19.
	 * Типичная имплементация должна быть такой: return new CardReaderChannel( this, logicalChannel );
	 * При реализации метода у потомков в retrun value будет задан тип потомка. 
	 */
	public abstract CardReader getCardChannel( int logicalChannel );

	// =================================================================================================================
	// Методы Cmd проверяют ожидаемый статус, логируют CApdu и RApdu, накладывают SM, замеряется время выполнения команд.
	// Последнее RApdu запоминаятся в полях this.rapdu, this.resp.
	// =================================================================================================================
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить CApdu и проверить ожидаемый статус.
	 * @param capdu - Командное APDU.
	 * @param expectedStatus - Ожидаемый статус, см. также RApdu.ST*.
	 *     Если статус не соответствует ожидаемому - исключение.
	 */
	public final RApdu Cmd( CApdu capdu, int expectedStatus )
	{
		return Cmd( this.sm, capdu, expectedStatus );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Удобство: CApdu в виде HEX-строки.
	 */
	public final RApdu Cmd( String capduHex, int expectedStatus )
	{
		return Cmd( new CApdu( capduHex ), expectedStatus );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Удобство: Ожидаемый статус = RApdu.ST_OK - успешное выполнение команды.
	 */
	public final RApdu Cmd( CApdu capdu )
	{
		return Cmd( capdu, RApdu.ST_OK );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Удобство: Ожидаемый статус = RApdu.ST_OK - успешное выполнение команды.
	 * Удобство: CApdu в виде HEX-строки.
	 */
	public final RApdu Cmd( String capduHex )
	{
		return Cmd( new CApdu( capduHex ), RApdu.ST_OK );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Удобство: CApdu задаётся по частям HEX-строками.
	 * Удобство: Ожидаемый статус = RApdu.ST_OK - успешное выполнение команды.
	 * @param headerHex - Заголовок CApdu в виде HEX-строки, 4 байта: CLA INS P1 P2.
	 * @param dataFieldHex - Поле данных CApdu.
	 * @param Ne - Размер ожидаемого ответа.
	 */
	public final RApdu Cmd( String headerHex, String dataFieldHex, int Ne )
	{
		return Cmd( new CApdu( headerHex, dataFieldHex, Ne ), RApdu.ST_OK );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить CApdu под SM и проверить ожидаемый статус.
	 * @param sm - объект, накладывающий Secure Messaging, может быть null.
	 * @param capdu - Командное APDU.
	 * @param expectedStatus - Ожидаемый статус, см. также RApdu.ST*.
	 *     Если статус не соответствует ожидаемому - исключение.
	 */
	public RApdu Cmd( ISM sm, CApdu capdu, int expectedStatus )
	{
		String callClassName = (callerClassName == null) ? thisClassName : callerClassName;
		callerClassName = null;

		apduLogger.printBeforeCommand( capdu, callClassName );

		boolean isTlvData = capdu.isTlvData;
		if( sm != null ) // Encrypt
		{
			capdu = sm.encryptCommand( capdu );
			apduLogger.printCApduSM( capdu );
		}

		ticker.restart();
		rapdu = transmit( capdu ); // Execute command
		resp = rapdu.response;
		cmdTime = ticker.getDiffMs();
		sumTime += cmdTime;

		if( sm != null ) // Decrypt
		{
			apduLogger.printRApduSM( rapdu, false );
			if( rapdu.isOk() )
			{
				rapdu = sm.decryptResponse( rapdu );
				resp = rapdu.response;
			}
		}

		apduLogger.printAfterCommand( rapdu, cmdTime, isTlvData );

		rapdu.checkStatus( expectedStatus, callClassName );

		return this.rapdu;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param sm - объект, накладывающий Secure Messaging, может быть null.
	 * Удобство: Ожидаемый статус = RApdu.ST_OK - успешное выполнение команды.
	 */
	public final RApdu Cmd( ISM sm, CApdu capdu )
	{
		return Cmd( sm, capdu, RApdu.ST_OK );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать объект SM. Он будет использоваться для всех последующих команд.
	 * Это альтернатива передаче объекта SM в каждом Cmd,
	 * null - перестать использовать SM.
	 */
	public final void setSM( ISM sm )
	{
		this.sm = sm;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return - ссылка на заданный в setSM объект.
	 */
	public final ISM getSM()
	{
		return this.sm;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Освобождение всех ресурсов и закрытие всех каналов. 
	 */
	@Override
	public abstract void close();
}
