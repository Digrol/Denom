// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.*;
import org.denom.log.*;

/**
 * Абстрактный считыватель (ридер) смарт-карт.
 * Наследники реализуют конкретный транспорт до ридера, например PC/SC, Socket, AndroidNFC.
 * 
 * Пример использования:
 * CardReader cr = new CardReader***().setApduLog( apduLog );
 * cr.connect( "reader name" );
 * cr.powerOn();
 * cr.Cmd( myApduHelper(...) ); // Проверяется статус выполнения команды
 * cr.powerOff();
 * cr.close();
 * 
 * Метод 'transmit' НЕ проверяет статус выполнения команды картой, в Apdu log не пишет.
 * Только использование транспорта напрямую.
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
	// Флаг наличия объекта-лога, для оптимизации
	protected boolean isTransportLog;

	protected ILog apduLog;
	
	protected ISM mSM = null;

	private Ticker ticker = new Ticker();

	private final String thisClassName = CardReader.class.getName();
	private IApduLogger apduLogger = new APDULoggerNothing();

	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	protected CardReader() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать лог для логирования транспортного уровня.
	 * null или LogDummy - не логировать.
	 */
	public CardReader setTransportLog( ILog log )
	{
		isTransportLog = (log != null) && !(log instanceof LogDummy);
		this.transportLog = log;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public final ILog getTransportLog()
	{
		return transportLog;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать лог для логирования APDU.
	 * null или LogDummy - не логировать.
	 */
	public final CardReader setApduLog( ILog log )
	{
		this.apduLog = log;
		apduLogger = (log != null) && !(log instanceof LogDummy) ?
				new APDULoggerTypical( log ) : new APDULoggerNothing();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public final ILog getApduLog()
	{
		return apduLog;
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
	public final Binary powerOn()
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
	public final void powerOff()
	{
		apduLogger.printPowerOff();
		powerOffImpl();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * powerOff и powerOn
	 * @return - ответ карты (ATR).
	 */
	public final Binary reset()
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
		return Cmd( mSM, capdu, expectedStatus );
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
	public final RApdu Cmd( ISM sm, CApdu capdu, int expectedStatus )
	{
		String callClassName = (callerClassName == null) ? thisClassName : callerClassName;
		callerClassName = null;

		apduLogger.printBeforeCommand( capdu, callClassName );

		boolean isTlvData = capdu.isTlvData;
		if( sm != null ) // Зашифровать
		{
			capdu = sm.encryptCommand( capdu );
			apduLogger.printCApduSM( capdu );
		}

		ticker.restart();
		rapdu = transmit( capdu ); // Выполнение команды
		resp = rapdu.response;
		cmdTime = ticker.getDiffMs();
		sumTime += cmdTime;

		if( sm != null ) // Расшифровать
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
		mSM = sm;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return - ссылка на заданный в setSM объект.
	 */
	public final ISM getSM()
	{
		return mSM;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Освобождение всех ресурсов и закрытие всех каналов. 
	 */
	@Override
	public abstract void close();

	// =================================================================================================================
	// Печать в apduLog вынесена в отдельный класс для ясности логики выполнения команды.
	// В будущем возможна кастомизация печати.
	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	private static interface IApduLogger
	{
		public void printPowerOn();
		public void printPowerOff();
		public void printReset();
		public void printATR( Binary atr );
		public void printBeforeCommand( CApdu capdu, String callClassName );
		public void printCApduSM( CApdu capduSM );
		public void printRApduSM( RApdu rapduSM, boolean isTlvData );
		public void printAfterCommand( RApdu rapdu, long commandTime, boolean isTlvData );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static class APDULoggerNothing implements IApduLogger
	{
		public void printPowerOn() {}
		public void printPowerOff() {}
		public void printReset() {}
		public void printATR( Binary atr ) {}
		public void printBeforeCommand( CApdu capdu, String callClassName ) {}
		public void printCApduSM( CApdu capduSM ) {}
		public void printRApduSM( RApdu rapduSM, boolean isTlvData ) {}
		public void printAfterCommand( RApdu rapdu, long commandTime, boolean isTlvData ) {}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private class APDULoggerTypical implements IApduLogger
	{
		ILog log;
		
		APDULoggerTypical( ILog log )
		{
			this.log = log;
		}

		public void printPowerOn()
		{
			log.writeln( Colors.CYAN_I, "Power on" );
		}

		public void printPowerOff()
		{
			log.writeln( Colors.CYAN_I, "Power off" );
		}

		public void printReset()
		{
			log.writeln( Colors.CYAN_I, "Reset" );
		}

		public void printATR( Binary atr )
		{
			log.writeln( Colors.CYAN_I, "ATR: " + atr.Hex() );
		}

		public void printBeforeCommand( CApdu capdu, String callClassName )
		{
			log.writeln( Colors.CYAN, "----------------------------------------------------------------" );
			log.write( Colors.YELLOW, Strings.currentDateTime() + " -- " );
			log.writeln( Colors.YELLOW, Ex.getCallerPlace( callClassName ) );
			capdu.print( log, Colors.GRAY, Colors.CYAN_I, 0 );
		}

		public void printCApduSM( CApdu capduSM )
		{
			log.writeln( Colors.DARK_GRAY, "    +++++++++++++++ Secure Messaging +++++++++++++++" );
			capduSM.print( log, Colors.DARK_GRAY, 0, 4 );
		}

		public void printRApduSM( RApdu rapduSM, boolean isTlvData )
		{
			log.writeln( Colors.DARK_GRAY, "    ~~~~~~~~~~~~~" );
			rapduSM.print( log, Colors.DARK_GRAY, 4, isTlvData );
			log.writeln( Colors.DARK_GRAY, "    +++++++++++++++ Secure Messaging +++++++++++++++" );
		}

		public void printAfterCommand( RApdu rapdu, long commandTime, boolean isTlvData )
		{
			log.writeln( Colors.GRAY, "-------------------------" );
			rapdu.print( log, Colors.GRAY, 0, isTlvData );
			log.writeln( Colors.MAGENTA, "Command time: " + commandTime + " ms" );
			log.writeln( Colors.CYAN, "----------------------------------------------------------------" );
		}
	}

}
