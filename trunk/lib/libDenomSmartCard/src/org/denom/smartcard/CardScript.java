// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import java.util.*;
import org.denom.*;
import org.denom.log.*;

import static org.denom.Ex.*;

/**
 * Класс предназначен для написания простых приложений, использующих смарт-карту (скрипт).
 *
 * Использование: наследоваться от класса CardScript и реализовать метод Script.
 * Задать настройки (см. CardScript.Options), вызвать метод 'run'.
 * Метод 'run' инициализирует логи, текущий ридер и вызывает callback Script().
 * 
 * Предполагается, что в методе Script используются, в основном:
 * методы класса CardReader; Utils; Binary; криптографичекие классы;
 * хелперы (формирование CApdu) для соответствующего карточного приложения.
 */
public abstract class CardScript implements Runnable
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Настройки скрипта для работы со смарт-картами.
	 */
	public static class Options
	{
		/**
		 * Настройки ридера.
		 */
		public CardReaderOptions reader = new CardReaderOptions();
		
		/**
		 * Настройки логирования.
		 */
		public LogOptions log = new LogOptions();
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public static class LogOptions
	{
		/**
		 * Консольный лог:
		 *   0 - не вести;
		 *   1 - стандартная консоль (поток вывода);
		 *   2 - отдельное графическое окно swing.
		 */
		public int console = 2;

		/**
		 * Вести файловый лог.
		 */
		public boolean file = false;
		
		/**
		 * Печатать в лог все APDU.
		 */
		public boolean apdu = false;

		/**
		 * Печатать в лог все TPDU (транспортный лог ридера).
		 */
		public boolean tpdu = false;
	}

	/**
	 * Настройки скрипта.
	 * Обычно используется чтобы задать текущий ридер и лог в методе run. 
	 */
	public Options opt = new Options();

	// =================================================================================================================
	/**
	 * Текущий ридер. Обычно в скрипте достаточно одного ридера.
	 */
	public CardReader cr = new CardReaderNull();

	/**
	 * Последний ответ от текущего ридера.
	 */
	public RApdu rapdu = cr.rapdu;
	public Binary resp = cr.resp;

	/**
	 * Лог скрипта.
	 */
	public ILog log = new LogDummy();

	/**
	 * Лог для APDU.
	 */
	public ILog logApdu = new LogDummy();
	
	/**
	 * Для генерации случайных чисел в скрипте.
	 */
	protected Random rand = new Random( System.nanoTime() );

	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить скрипт.
	 */
	public void Main()
	{
		initLog();

		try
		{
			log.writeln( Colors.DARK_GRAY, "==================================================================" );
			log.writeln( Colors.CYAN_I, "Current time: " + Strings.currentDateTime()  );

			cr = createReader( opt.reader );
			if( opt.log.tpdu )
			{
				cr.setTransportLog( log );
			}

			if( opt.log.apdu )
			{
				logApdu = log;
				cr.setApduLog( logApdu );
			}

			Ticker t = new Ticker();

			if( !(cr instanceof CardReaderNull) )
				cr.powerOn();

			log.writeln( Colors.MAGENTA_I, "-- Script begin --" );
			run();
			log.writeln( Colors.MAGENTA_I, "-- Script end --" );

			if( !(cr instanceof CardReaderNull) )
				cr.powerOff();

			cr.close();

			log.writeln( Colors.MAGENTA_I, "Summary command time = " + cr.sumTime + " ms" );
			log.writeln( Colors.MAGENTA_I, "Summary time = " + t.getDiffMs() + " ms" );
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.ERROR, "Error: " + Ex.getErrorDescription( ex ) );
			throw new RuntimeException( "Ошибка при выполнении скрипта" );
		}
	}

	// =================================================================================================================
	private final static String className = CardScript.class.getName();
	/**
	 * Удобство: сокращение записи для скриптов: cr.Cmd(...) -> Cmd(...)
	 * См. CardReader.Cmd
	 */
	public final void Cmd( CApdu capdu, int expectedStatus )
	{
		cr.callerClassName = className;
		rapdu = cr.Cmd( capdu, expectedStatus );
		resp = rapdu.response;
	}

	public final void Cmd( String capduHex, int expectedStatus )
	{
		Cmd( new CApdu( capduHex ), expectedStatus );
	}

	public final void Cmd( CApdu capdu )
	{
		Cmd( capdu, RApdu.ST_OK );
	}

	public final void Cmd( String capduHex )
	{
		Cmd( new CApdu( capduHex ), RApdu.ST_OK );
	}

	public final void Cmd( String headerHex, String dataFieldHex, int Ne )
	{
		Cmd( new CApdu( headerHex, dataFieldHex, Ne ), RApdu.ST_OK );
	}

	public final void Cmd( ISM sm, CApdu capdu, int expectedStatus )
	{
		cr.callerClassName = className;
		rapdu = cr.Cmd( sm, capdu, expectedStatus );
		resp = rapdu.response;
	}

	public final void Cmd( ISM sm, CApdu capdu )
	{
		Cmd( sm, capdu, RApdu.ST_OK );
	}

	// =================================================================================================================
	/**
	 * Удобство: сокращение записи для скриптов: log.write*( ... ) -> write*( ... )
	 * @param text
	 */
	public void write( String text )
	{
		log.write( text );
	}

	public void write( int color, String text )
	{
		log.write( color, text );
	}

	public void writeln( String text )
	{
		log.writeln( text );
	}

	public void writeln( int color, String text )
	{
		log.writeln( color, text );
	}
	
	// =================================================================================================================
	/**
	 * Проверить ответ карты в текущем ридере на последнюю выполненную команду.
	 * Если данные не совпадут - исключение.
	 * @param needResponse - такие данные карта должна была вернуть.
	 */
	public void checkResp( final Binary needResponse )
	{
		MUST( needResponse.equals( cr.resp ), "Некорректный ответ карты" );
	}

	public void checkResp( final String needResponse )
	{
		checkResp( new Binary( needResponse ) );
	}

	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	// Создать экземляры логов в соответствии с настройками.
	private void initLog()
	{
		String logName = getClass().getSimpleName();

		if( opt.log.console == 1 )
		{
			consoleLog = new LogConsole();
		}
		else if( opt.log.console == 2 )
		{
			LogColoredConsoleWindow log = new LogColoredConsoleWindow( logName );
			log.setDefaultColor( Colors.GREEN );
			consoleLog = log;
		}

		log = consoleLog;

		if(  opt.log.file )
		{
			log = new LogFile( logName + ".log", true ).setNext( consoleLog );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить строку введённую пользователем в окно или консоль (в зависимости от лога).
	 */
	public String readln()
	{
		String str = "";

		if( consoleLog instanceof LogColoredConsoleWindow )
		{
			str = ((LogColoredConsoleWindow)consoleLog).readln();
			log.writeln( Colors.YELLOW_I, str );
		}
		else
		{
			// не закрываем ресурс, так как System.in управляется JVM
			@SuppressWarnings("resource")
			Scanner sc = new Scanner( System.in );

			if( sc.hasNext() )
			{
				str = sc.next();
			}
		}

		return str;
	}

	private final static String MODEL_PREFIX = "vc";
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Диалог выбора имени VR-ридера из списка ридеров, полученных с хоста.
	 */
	private void chooseVrReader( CardReaderOptions opt )
	{
		if( (opt.vrName == null) || opt.vrName.isEmpty() )
		{
			String[] names;
			try( VirtualReaderClient client = new VirtualReaderClient( opt.vrHost, opt.vrPort ) )
			{
				names = client.commandEnumReaders();
			}

			// Отфильтруем модели карт из списка
			ArrayList<String> arr = new ArrayList<>( names.length );
			ArrayList<String> models = new ArrayList<>( names.length );
			for( String name : names )
			{
				if( name.startsWith( MODEL_PREFIX ) )
				{
					models.add( name );
				}
				else
				{
					arr.add( name );
				}
			}
			if( !models.isEmpty() )
			{
				arr.add( MODEL_PREFIX );
			}
			log.writeln( Colors.DARK_GRAY, "VR Host - " + opt.vrHost + ":" + opt.vrPort );
			opt.vrName = makeChoice( "Choose VR Reader Name:", arr );

			if( opt.vrName.equals( MODEL_PREFIX ) )
			{
				log.writeln( Colors.DARK_GRAY, "VR Host - " + opt.vrHost + ":" + opt.vrPort );
				opt.vrName = makeChoice( "Choose VR Model:", models );
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/// Спросить у пользователя, с каким ридером работать, если ридер ещё не определён.
	public void chooseReaderType( CardReaderOptions opt )
	{
		if( (opt.type == null) || opt.type.isEmpty() || opt.type.equals( ReaderType.UNKNOWN ) )
		{
			log.writeln( Colors.DARK_GRAY, "PC/SC readers:" );

			String[] pcscReaders = CardReaderPCSC.enumerateReaders();
			for( int i = 0; i < pcscReaders.length; ++i )
			{
				log.writeln( Colors.DARK_GRAY, "  " + (i+1) + " - " + pcscReaders[ i ] );
			}
			log.writeln( Colors.DARK_GRAY, "Virtual readers:" );
			log.writeln( Colors.DARK_GRAY, "  q - " + ReaderType.VR );

			log.write( Colors.YELLOW_I, "Enter reader index: " );
			String choice = readln();
			switch( choice )
			{
				case "Q": case "q":
					opt.type = ReaderType.VR;
					break;

				default: // PC/SC
					int index = Integer.parseInt( choice );
					MUST( (index > 0) && (index <= pcscReaders.length ), "Некорректный номер ридера" );
					opt.type = ReaderType.PCSC;
					opt.pcscName = pcscReaders[ index - 1 ];
			}
		}

		if( opt.type.equals( ReaderType.VR ) )
		{
			chooseVrReader( opt );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создаёт экземпляр ICardReader в зависимости от настроек в opt.
	 * Если opt.type не задан, то диалог с пользователем для выбора.
	 * После выбора типа opt.type и opt.pcscName будут установлены в выбранные значения.
	 * @param opt - настройки ридера.
	 * @return - созданный экземпляр ICardReader.
	 */
	public CardReader createReader( CardReaderOptions opt )
	{
		chooseReaderType( opt );

		log.writeln( Colors.MAGENTA_I, "Reader Type:  " + opt.type );

		String nameStr = "";
		switch( opt.type )
		{
			case ReaderType.PCSC:
				nameStr = "PC/SC name:  " + opt.pcscName;
				if( opt.pcscName.startsWith( "#" ) ) // Выбор по порядковому номеру
				{
					MUST( opt.pcscName.length() == 2, "Некорректное имя PC/SC ридера" );
					int index = Integer.parseInt( opt.pcscName.substring( 1 ) );
					String[] pcscReaders = CardReaderPCSC.enumerateReaders();
					MUST( (index > 0) && (index <= pcscReaders.length), "Некорректный номер PC/SC ридера" );
					nameStr += "  =  " + pcscReaders[ index - 1 ];
				}
				break;

			case ReaderType.PCSCNative:
				nameStr = "PC/SC name:  " + opt.pcscName;
				if( opt.pcscName.startsWith( "#" ) ) // Выбор по порядковому номеру
				{
					MUST( opt.pcscName.length() == 2, "Некорректное имя PC/SC ридера" );
					int index = Integer.parseInt( opt.pcscName.substring( 1 ) );
					CardReaderPCSCNative r = new CardReaderPCSCNative( opt.pcscNativeDll );
					String[] pcscReaders = r.enumReaders();
					r.close();
					MUST( (index > 0) && (index <= pcscReaders.length), "Некорректный номер PC/SC ридера" );
					nameStr += "  =  " + pcscReaders[ index - 1 ];
				}
				break;

			case ReaderType.VR:
				nameStr = "VR: " + opt.vrHost + ":" + opt.vrPort + ", name: " + opt.vrName;
				break;

			case ReaderType.NULL:
				cr = new CardReaderNull();
				break;

			default:
				THROW( "Unknown Reader Type" );
		}

		log.writeln( Colors.MAGENTA_I, nameStr );

		return ReaderFactory.create( opt, true );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Диалог с пользователем для выбора одного элемента из списка.
	 * @param description - Описание, что выбираем. Выводится в лог.
	 * @param values - Список вариантов. Элементы должны приводиться к строке.
	 * @return - выбранный пользователем вариант (одна из строк списка).
	 */
	public String makeChoice( String description, List<?> values )
	{
		log.writeln( Colors.DARK_GRAY, description );

		for( int i = 0; i < values.size(); ++i )
		{
			log.writeln( Colors.DARK_GRAY, (i+1) + " - " + values.get( i ).toString() );
		}

		log.write( Colors.YELLOW_I, "Enter index: " );

		int choice = Integer.parseInt( readln() );
		MUST( (choice > 0) && (choice <= values.size()), "Некорректный индекс" );

		return values.get( choice - 1 ).toString();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private ILog consoleLog = new LogDummy();
}
