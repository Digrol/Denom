// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5;

import java.net.*;
import java.util.concurrent.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.net.SocketClient;

import static org.denom.Ex.*;

// ----------------------------------------------------------------------------------------------------------------
/**
 * Клиент, который подключается к серверному порту и принимает D5Commands.
 * В ответ шлёт D5Response-ы.
 * Работает асинхронно. Т.е. может принять множество команд, а ответы послать позже и в произвольном порядке.
 * Запускает несколько потоков: 1 поток для считывания команд; N потоков для обработки команд и отправки ответов.
 * Для остановки потоков, следует вызвать метод 'close'.
 * Поддерживает соединение живым, раз в keepAliveIntervalSec секунд
 */
public abstract class D5ReverseClient implements AutoCloseable
{
	private ILog log = new LogDummy();
	private boolean printD5 = false;

	private SocketClient socketClient = null;

	/**
	 * Limit for data size accepted from server.
	 */
	private int commandDataLimit = 1_000_000;

	/**
	 * Поток, читающий команды из сокета.
	 */
	private ExecutorService readSocketExecutor;

	private Runnable onClosed;
	
	/**
	 * Потоки, обрабатывающие команды. Они же отправляют свои ответы в сокет.
	 */
	private ExecutorService workersExecutor;

	/**
	 * Поток KEEP ALIVE, который отправляет ответ на команду ENUM_COMMANDS,
	 * чтобы соединение с сервером не разрывалось
	 */
	private int keepAliveIntervalSec = 20;
	ScheduledExecutorService keepAliveExecutor;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param numWorkerThreads - количество рабочих поток для обработки команд.
	 * @param prefixNameForThreads - префикс для имен потоков.
	 */
	public D5ReverseClient( int numWorkerThreads, String prefixNameForThreads )
	{
		readSocketExecutor = Executors.newFixedThreadPool( 1,
				new ThreadFactoryNamed( prefixNameForThreads + "-SocketReader", Thread.NORM_PRIORITY + 2, 0, false ) );

		workersExecutor = Executors.newFixedThreadPool( numWorkerThreads,
				new ThreadFactoryNamed( prefixNameForThreads + "-Worker", Thread.NORM_PRIORITY, 0, false ) );

		keepAliveExecutor = Executors.newScheduledThreadPool( 1 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать лог для вывода сообщений об ошибках. Если вызвать метод setPrintD5, то будут выводиться все команды.
	 */
	// -----------------------------------------------------------------------------------------------------------------
	public void setLog( ILog log )
	{
		MUST( log != null, "Null params" );
		this.log = log;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * С этим интервалом отправлять на сервер ответ на ENUM COMMANDS, чтобы соединение не разрывалось.
	 */
	public void setKeepAliveInterval( int intervalSec )
	{
		this.keepAliveIntervalSec = intervalSec;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Callback, вызывается в методе close, чтобы сообщить пользователю класса о закрытии соединения с сервером.
	 */
	public void setOnClosed( Runnable onClosed )
	{
		MUST( (onClosed != null), "Null params" );
		this.onClosed = onClosed;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать максимальный размер данных, принимаемых в одной команде.
	 */
	public void setCommandDataLimit( int commandDataLimit )
	{
		this.commandDataLimit = commandDataLimit;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Print all D5 commands and responses to log.
	 */
	public void setPrintD5( boolean isPrintD5 )
	{
		this.printD5 = isPrintD5;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подключиться можно только 1 раз. После метода close() или для повторного подключения следует создать новый экземпляр.
	 */
	public synchronized void connect( String host, int port, int connectTimeoutSec )
	{
		MUST( this.socketClient == null, "Client already connected." );
		SocketClient socket = new SocketClient( connectTimeoutSec );
		socket.connectHard( host, port );
		this.socketClient = socket;

		// Запуск цикла считывания команд
		readSocketExecutor.execute( this::readCommands );

		keepAliveExecutor.scheduleAtFixedRate( this::sendKeepAlive, keepAliveIntervalSec, keepAliveIntervalSec, TimeUnit.SECONDS );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return ссылка на сокет для управления соединением снаружи.
	 */
	public SocketClient getSocketClient()
	{
		return socketClient;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary keepAliveBin = null;
	// -----------------------------------------------------------------------------------------------------------------
	private synchronized void sendKeepAlive()
	{
		if( keepAliveBin == null )
		{
			D5Response response = new D5Response();
			response.code   = D5Command.ENUM_COMMANDS - 0x20000000;
			response.status = 0;
			response.index  = 0;
			response.data   = new Binary();

			keepAliveBin = new Binary();
			response.encode( keepAliveBin );
		}

		if( printD5 )
		{
			log.writeln( "D5 Response: " + keepAliveBin.Hex( 4, 0, 0, 0 ) );
		}
		socketClient.write( keepAliveBin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Цикл чтения команды из сокета, выполняется в readSocketExecutor
	 */
	private void readCommands()
	{
		try
		{
			Binary buf = new Binary().reserve( 512 );

			Socket socket = socketClient.getSocket();
			socketClient.getSocket().setSoTimeout( 0 );

			while( !socket.isClosed() )
			{
				buf.clear();

				// Read D5 Command header (12 bytes)
				socketClient.read( buf, 12 );

				// Read Command data
				int dataSize = buf.getIntBE( 8 );
				MUST( (dataSize >= 0) && (dataSize <= commandDataLimit), "Too large D5Command from server" );
				socketClient.read( buf, dataSize );

				// D5 Command recieved
				if( printD5 )
				{
					log.writeln( "D5 Command : " + buf.Hex( 4, 0, 0, 0 ) );
				}

				D5Command command = new D5Command();
				command.decode( buf );
				workersExecutor.execute( () -> onCommand( command ) );
			}
		}
		catch( Throwable ex )
		{
			if( !Thread.interrupted() )
			{
				log.writeln( Colors.YELLOW_I, ex.toString() );
			}
		}
		finally
		{
			// Вызываем в отдельном потоке, т.к. close закрывает и текущий поток тоже
			new Thread( () ->
			{
				try
				{
					this.close();
				}
				catch( Throwable ex )
				{
					log.writeln( Colors.RED_I, ex.toString() );
				}
			}, "Closing D5 reverse client" ).start();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Обработчик команд, вызывается в одном из рабочих потоков при получении очередной команды с сервера.
	 * Возвращает данные для ответа ответа.
	 * За отправку ответа отвечает этот класс, поэтому onCommandDispatch может выбрасывать исключения, тогда
	 * будет отправлен ответ с описанием ошибки.
	 * @return Если метод вернёт null, то ответ не будет отправлен вообще
	 */
	protected abstract Binary onCommandDispatch( final D5Command command );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызывается в одном из рабочих потоков для обработки команд
	 */
	private void onCommand( final D5Command command )
	{
		Binary responseData = null;
		int status = D5Response.STATUS_OK;

		try
		{
			responseData = onCommandDispatch( command );
		}
		catch( Ex ex )
		{
			status = D5Response.STATUS_UNKNOWN_ERROR;
			if( (ex.code & 0xE0000000) == 0xE0000000 )
			{
				status = ex.code;
			}
			responseData = new Binary().fromUTF8( ex.getMessage() );
		}
		catch( Throwable ex )
		{
			status = D5Response.STATUS_UNKNOWN_ERROR;
			responseData = new Binary().fromUTF8( ex.toString() );
		}

		if( responseData != null )
		{
			D5Response response = new D5Response();
			response.code   = command.code - 0x20000000;
			response.status = status;
			response.index  = command.index;
			response.data   = responseData;

			Binary bin = new Binary();
			response.encode( bin );

			// Отправка ответов по очереди
			synchronized( this )
			{
				if( printD5 )
				{
					log.writeln( "D5 Response: " + bin.Hex( 4, 0, 0, 0 ) );
				}
				socketClient.write( bin );
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public synchronized boolean isClosed()
	{
		return readSocketExecutor == null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public synchronized void close()
	{
		// Этот метод вызывается либо снаружи, либо из блока finally цикла чтения,
		// поэтому обеспечиваем работу этого метода при повторных вызовах.
		// Также даёт возможность вызывать close() пользователям

		if( keepAliveExecutor != null )
		{
			Sys.shutdownNow( keepAliveExecutor, 3 );
			keepAliveExecutor = null;
		}

		if( readSocketExecutor != null )
		{
			Sys.shutdownNow( readSocketExecutor, 3 );
			readSocketExecutor = null;
		}

		if( workersExecutor != null )
		{
			Sys.shutdownNow( workersExecutor, 10 );
			workersExecutor = null;
		}

		if( socketClient != null )
		{
			socketClient.close();
		}

		if( onClosed != null )
		{
			onClosed.run();
			onClosed = null;
		}
	}
}