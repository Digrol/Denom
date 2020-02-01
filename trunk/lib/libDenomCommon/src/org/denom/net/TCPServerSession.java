// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.denom.Ex.*;

// -----------------------------------------------------------------------------------------------------------------
public abstract class TCPServerSession
{
	/**
	 * Задаётся в конструкторе.
	 */
	protected final SocketChannel socket;
	protected final TCPServer tcpProcessor;

	/**
	 * Задаётся в TCPServer-е после создания экземпляра сессии.
	 */
	protected SelectionKey selectionKey = null;

	public InetSocketAddress remoteAddress;

	protected volatile ConcurrentLinkedQueue<ByteBuffer> writeQueue = new ConcurrentLinkedQueue<>();


	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Для создания других инстансов вызовом метода newInstance
	 */
	protected TCPServerSession()
	{
		this.socket = null;
		this.tcpProcessor = null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызывается в ioThread-е, когда от нового клиента получен запрос на подключение к серверу.
	 * В классе-наследнике создаётся экземпляр сессии.
	 * Если возвращается null или выбрасывается исключение, то TCPServer закроет клиентский сокет -
	 * отказ в установлении сессии.
	 * В этом методе можно настроить сокет, например:
	 *   clientSocket.socket().setSoLinger( true, 0 );
	 * По умолчанию, в TCPServer-е до вызова этого метода для сокета отключается алгоритм Нейгла.
	 * В классе-наследнике можно включить, если нужен.
	 */
	public abstract TCPServerSession newInstance( TCPServer tcpServer, SocketChannel clientSocket );

	// -----------------------------------------------------------------------------------------------------------------
	protected TCPServerSession( TCPServer tcpProcessor, SocketChannel clientSocket )
	{
		this.socket = clientSocket;
		this.tcpProcessor = tcpProcessor;

		try
		{
			this.remoteAddress = (InetSocketAddress)clientSocket.getRemoteAddress();
		}
		catch( IOException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void close()
	{
		writeQueue.clear();
		try
		{
			selectionKey.cancel();
			socket.close();
		}
		catch( IOException ex ) {}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызывается в ioThread-е.
	 * В классе-наследнике необходимо считать из socket-а все имеющиеся данные.
	 */
	protected abstract void readFromSocket();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Может вызываться в различных потоках.
	 */
	public void writeToSocket( ByteBuffer buf )
	{
		writeQueue.offer( buf );
		tcpProcessor.needToFlush( this );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызывается после передачи всего буфера в сокет.
	 * buf уже удалён из очереди.
	 * В наследниках можно реализовывать различную реакцию:
	 * например, продолжить генерацию контента или закрыть сокет.
	 * Метод вызывается в ioThread-е, соответственно, не рекомендуется делать долгие операции.
	 */
	protected void onWritten( ByteBuffer buf ) {}

}