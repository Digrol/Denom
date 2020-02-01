// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;

import org.denom.*;
import org.denom.log.*;

import static org.denom.Ex.*;

/**
 * Открывает серверный сокет, создаёт селектор на сетевые события в этом сокете, принимает и передаёт данные.
 * Логика обработки данных - в наследниках TCPServerSession.
 */
public class TCPServer
{
	private final ILog log;

	private final ServerSocketChannel serverSocket;
	private Selector selector;
	private final ExecutorService ioExecutor;
	private final TCPServerSession sessionConstructor;

	private final Queue<TCPServerSession> flushingSessions = new ConcurrentLinkedQueue<>();

	private AtomicBoolean wakeupCalled = new AtomicBoolean( false );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param sessionConstructor - на каждый новый клиентский запрос но подключение будет вызван фабричный метод
	 * sessionConstructor.nеwInstance(...) для создания экземпляра сессии.
	 */
	public TCPServer( ILog log, String host, int port, TCPServerSession sessionConstructor )
	{
		this.log = log;
		this.sessionConstructor = sessionConstructor;
		
		ioExecutor = Executors.newFixedThreadPool( 1,
				new ThreadFactoryNamed( this.getClass().getSimpleName(), Thread.NORM_PRIORITY, 0 ) );

		try
		{
			serverSocket = ServerSocketChannel.open();
			serverSocket.configureBlocking( false );

			InetSocketAddress localAddr = host.isEmpty() ? new InetSocketAddress( port ) : new InetSocketAddress( host, port );
			serverSocket.bind( localAddr, 300 );

			selector = Selector.open();
			serverSocket.register( selector, SelectionKey.OP_ACCEPT );

			ioExecutor.execute( () -> ioLoop() );
		}
		catch( IOException ex )
		{
			throw new Ex( "Can't open server socket" + ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void recreateSelector() throws IOException
	{
		Set<SelectionKey> keys = selector.keys();
		Selector newSelector = Selector.open();

		for( SelectionKey key : keys )
		{
			SelectableChannel ch = key.channel();
			if( ch instanceof ServerSocketChannel )
			{
				ch.register( newSelector,  key.interestOps(), key.attachment() );
			}
			else
			{
				TCPServerSession session = (TCPServerSession)key.attachment();
				SelectionKey newKey = ch.register( newSelector, key.interestOps(), session );
				session.selectionKey = newKey;
			}
		}

		selector.close();
		selector = newSelector;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызывается в различных потоках.
	 */
	void needToFlush( TCPServerSession session )
	{
		flushingSessions.offer( session );
		wakeup();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызывается в ioThread-е.
	 */
	private void flush( TCPServerSession session )
	{
		try
		{
			SelectionKey key = session.selectionKey;
			while( !session.writeQueue.isEmpty() )
			{
				ByteBuffer buf = session.writeQueue.peek();

				session.socket.write( buf );

				if( buf.remaining() != 0 )
				{
					// TCP-буфер заполнен, ждём, когда появится место.
					key.interestOps( key.interestOps() | SelectionKey.OP_WRITE );
					return;
				}
				else
				{
					session.writeQueue.remove();
					session.onWritten( buf );
				}
			}

			// все данные отправлены, выходим из ожидания 
			key.interestOps( key.interestOps() & ~SelectionKey.OP_WRITE );
		}
		catch( Exception ex ) // IOException + возможно CancelledKeyException
		{
			session.close();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызывается в ioThread-е.
	 */
	private void acceptClient( SocketChannel clientSocket ) throws IOException
	{
		try
		{
			clientSocket.configureBlocking( false );
			// По умолчанию, отключаем алгоритм Нейгла.
			clientSocket.socket().setTcpNoDelay( true );

			TCPServerSession newSession = sessionConstructor.newInstance( this, clientSocket );
			MUST( newSession != null );
			SelectionKey clientKey = clientSocket.register( selector, SelectionKey.OP_READ );
			clientKey.attach( newSession );
			newSession.selectionKey = clientKey;
		}
		catch( Throwable ex )
		{
			clientSocket.close();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызывается в различных потоках.
	 */
	void wakeup()
	{
		wakeupCalled.getAndSet( true );
		selector.wakeup();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void ioLoop()
	{
		try
		{
			Thread.currentThread().setPriority( 8 );

			int tries = 5;

			while( serverSocket.isOpen() && !Thread.currentThread().isInterrupted() )
			{
				long t0 = System.currentTimeMillis();
				int selected = selector.select( 1000 );
				long t1 = System.currentTimeMillis();
				long delta = t1 - t0;

				if( !wakeupCalled.getAndSet( false ) && (selected == 0) && (delta < 100) )
				{	// Work around infamous epoll BUG
					if( tries == 0 )
					{
						recreateSelector();
						tries = 5;
					}
					else
					{
						tries--;
					}
					continue;
				}
				else
				{
					tries = 5;
				}

				for( Iterator<SelectionKey> iterator = selector.selectedKeys().iterator(); iterator.hasNext(); )
				{
					SelectionKey key = iterator.next();
					iterator.remove();
					try
					{
						if( key.isAcceptable() )
						{
							// Новый клиент хочет установить соединение
							ServerSocketChannel serverChannel = (ServerSocketChannel)key.channel();
							acceptClient( serverChannel.accept() );
						}
						else if( key.isWritable() )
						{
							flush( (TCPServerSession)key.attachment() );
						}
						else if( key.isReadable() )
						{
							((TCPServerSession)key.attachment()).readFromSocket();
						}
						
					}
					catch( IOException ex )
					{
						key.cancel();
						try
						{
							key.channel().close();
						}
						catch( IOException ex2 ) {}
					}
				}

				// Есть сессии с готовыми ответами, отправляем ответ
				while( !flushingSessions.isEmpty() )
				{
					flush( flushingSessions.poll() );
				}
			}
		}
		catch( ClosedByInterruptException ex )
		{
			return;
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.RED_I, ex.toString() );
		}
		finally
		{
			try
			{
				selector.close();
				serverSocket.close();
			}
			catch( Throwable ex ) {}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void close()
	{
		ioExecutor.shutdownNow();
		try
		{
			MUST( ioExecutor.awaitTermination( 3, TimeUnit.SECONDS ), "Can't stop TCP Server processor IO Loop" );
		}
		catch( InterruptedException ex )
		{
			THROW( ex ); // Interrupted while wait stop TCP Server processor IO Loop.
		}
	}

}
