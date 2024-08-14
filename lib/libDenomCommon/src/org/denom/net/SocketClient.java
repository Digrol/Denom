// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import org.denom.*;

import static org.denom.Ex.*;

/**
 * Клиентский сокет.
 * Надстройка над SocketChannel для упрощения работы с сокетом.
 *
 * Основной недостаток методов стандартных библиотечных классов - отсутствие метода считывания
 * заданного размера данных. Метод 'read' сокета считывает "сколько получилось в пределах заданного буфера",
 * поэтому для считывания всего объёма нужно писать цикл и контролировать объём принятых данных,
 * чтобы не переполнить доступную память клиента.
 * Для записи в сокет - тоже цикл.
 * 
 * В классе не задаётся предел на размер принимаемых данных.
 * Размер ограничен возможностями Binary, т.е. Integer.MAX_VALUE.
 *
 * Класс не хранит дополнительные буферы, используется только Binary, передаваемый снаружи,
 * в методах read и write, т.к. размеры данных в разных протоколах и задачах могут сильно отличаться.
 */
public class SocketClient implements AutoCloseable
{
	private SocketChannel socketChannel;

	/**
	 * Ссылка на socketChannel.socket()
	 */
	private Socket socket;

	// Проблема - нет возможности задать readTimeout для SocketChannel.
	// Когда нужно задать readTimeout используем getSocket().setSoTimeout( ms ).
	// Вызов getSocket().setSoTimeout( ms ) оказывает влияние на механизм, работающий с InputStream
	// в реализации Socket. Поэтому для чтения данных создается дополнительный channel, позволяющий работать 
	// с указанным InputStream (который берем из socketChannel).
	private ReadableByteChannel wrappedChannel;

	private int connectTimeoutMs;

	// -----------------------------------------------------------------------------------------------------------------
	public SocketClient()
	{
		this( 10 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать сокет, но подключение не устанавливать.
	 */
	public SocketClient( int connectTimeoutSec )
	{
		MUST( connectTimeoutSec > 0, "Can't set 'connectTimeout' <= 0" );
		this.connectTimeoutMs = connectTimeoutSec * 1000;

		createNewChannel();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сокет создан снаружи, просто запоминаем ссылку на него.
	 */
	public SocketClient( SocketChannel socketChannel )
	{
		this.socketChannel = socketChannel;
		this.socket = socketChannel.socket();
		if( socketChannel.isConnected() )
			initWrappedChannel();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void createNewChannel()
	{
		try
		{
			socketChannel = SocketChannel.open();
			socket = socketChannel.socket();
		}
		catch( IOException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void initWrappedChannel()
	{
		try
		{
			wrappedChannel = Channels.newChannel( socket.getInputStream() );
		}
		catch( IOException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Установить соединение с указанной машиной.
	 * @param host - имя или IP компьютера, к которому подключаемся.
	 *   Пустая строка - любой локальный адрес этой машины.
	 */
	public void connect( String host, int port )
	{
		connect( new InetSocketAddress( host.isEmpty() ? "0.0.0.0" : host, port ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void connect( InetSocketAddress addr )
	{
		try
		{
			socket.connect( addr, connectTimeoutMs );
		}
		catch( IOException ex )
		{
			THROW( ex.toString() );
		}

		initWrappedChannel();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Установить соединение с указанной машиной.
	 * Если сервер не примет соединение, либо возникнут другие ошибки при попытке подключения, то
	 * пытаться снова, пока соединение не будет установлено, в течение connectTimeoutSec (см. конструктор).
	 * @param host - имя или IP компьютера, к которому подключаемся.
	 *   Пустая строка - любой локальный адрес этой машины.
	 */
	public void connectHard( String host, int port )
	{
		host = host.isEmpty() ? "0.0.0.0" : host;
		InetSocketAddress destAddr = new InetSocketAddress( host, port );

		int curTimeout = connectTimeoutMs;
		while( !socket.isConnected() && (curTimeout >= 0) )
		{
			long t0 = System.currentTimeMillis();
			try
			{
				socket.connect( destAddr, curTimeout );
			}
			catch( Throwable ex )
			{
				curTimeout -= (int)(System.currentTimeMillis() - t0);
				if( curTimeout >= 0 )
				{
					try
					{
						Thread.sleep( 200 );
					}
					catch( InterruptedException ignored )
					{
						THROW( "InterruptedException" );
					}

					curTimeout -= 200;
					close();
					createNewChannel();
				}
			}
		}

		MUST( socketChannel.isConnected(), "Can't connect to " + host + ":" + port );
		initWrappedChannel();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void close()
	{
		try
		{
			socketChannel.close();
			if( wrappedChannel != null )
				wrappedChannel.close();
		}
		catch( IOException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Ссылка на объект this.socketChannel.
	 */
	public SocketChannel getChannel()
	{
		return socketChannel;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Ссылка на объект this.socketChannel.socket().
	 */
	public Socket getSocket()
	{
		return socket;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать из сокета (добавить в buf) заданное количество байт.
	 * Для прерывания операции считывания, можно закрыть сокет. При этом этот метод выбросит исключение. 
	 * @param buf - Буфер, в который будут считываться (добавляться) данные.
	 * @param needLen - Сколько байт требуется считатать.
	 *   При успешном завершении функции, размер буфер увеличится на needLen.
	 *   Память в buf резервируется в методе сразу требуемого размера.
	 */
	public void read( Binary buf, int needLen )
	{
		MUST( needLen >= 0, "Negative needLen argument" );
		if( needLen == 0 )
			return;

		int oldSize = buf.size();
		buf.resize( needLen + oldSize );

		ByteBuffer bb = ByteBuffer.wrap( buf.getDataRef(), oldSize, needLen );
		try
		{
			while( bb.hasRemaining() )
			{
				int size = wrappedChannel.read( bb );
				if( size <= 0 )
				{
					close();
					THROW( "Connection closed" );
				}
			}
		}
		catch( Throwable ex )
		{
			close();
			THROW( ex );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать какое-то количество байт из сокета, добавив их в buf.
	 * @param buf - Буфер, в который будут считываться (добавляться) данные.
	 * @param maxLen - максимальный размер данных, который мы ожидаем получить из сокета.
	 *   Память в buf резервируется в методе сразу максимального размера.
	 */
	public void readSome( Binary buf, int maxLen )
	{
		MUST( maxLen >= 0, "Negative maxLen argument" );
		if( maxLen == 0 )
			return;

		int oldSize = buf.size();
		buf.resize( maxLen + oldSize );

		ByteBuffer bb = ByteBuffer.wrap( buf.getDataRef(), oldSize, maxLen );
		try
		{
			int size = socketChannel.read( bb );
			if( size <= 0 )
			{
				close();
				THROW( "Connection closed" );
			}
			buf.resize( oldSize + size );
		}
		catch( Throwable ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Записать в сокет все данные из data.
	 */
	public void write( final Binary data )
	{
		ByteBuffer byteBuf = ByteBuffer.wrap( data.getDataRef(), 0, data.size() );
		try
		{
			while( byteBuf.hasRemaining() )
			{
				socketChannel.write( byteBuf );
			}
		}
		catch( Throwable ex )
		{
			THROW( ex.toString() );
		}
	}
	
}