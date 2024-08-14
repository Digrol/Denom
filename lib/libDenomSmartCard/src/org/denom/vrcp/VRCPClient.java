// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.vrcp;

import java.net.SocketException;

import org.denom.*;
import org.denom.log.*;
import org.denom.net.SocketClient;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

/**
 * Класс для клиента, отправляющего команды по протоколу VRCP.
 */
public class VRCPClient implements AutoCloseable
{
	/**
	 * Ограничение на размер принимаемых от сервера ответов по умолчанию.
	 */
	private static final int DEFAULT_VRAU_DATA_LIMIT = 500_000_000;

	/**
	 * Клиентский сокет для отправки VRCU и получения VRAU.
	 */
	private SocketClient socketClient = null;

	/**
	 * Ограничение на размер принимаемых от сервера ответов
	 */
	private int vrauDataLimit = DEFAULT_VRAU_DATA_LIMIT;

	/**
	 * Буфер для приёмо-передачи данных.
	 */
	private Binary buf = new Binary().reserve( 512 );

	private int commandIndex = 0;

	/**
	 * Оптимизация. Не создавать новые объекты при выполнении каждой команды.
	 */
	protected VRCU vrcu = new VRCU();
	protected VRAU vrau = new VRAU();

	protected ILog log = null;

	// -----------------------------------------------------------------------------------------------------------------
	public VRCPClient() {}

	// -----------------------------------------------------------------------------------------------------------------
	public VRCPClient( SocketClient socketClient )
	{
		this.socketClient = socketClient;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public VRCPClient( String host, int port )
	{
		this( host, port, 10 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструкор для краткости создания объекта в простых случаях.
	 */
	public VRCPClient( String host, int port, int connectTimeoutSec )
	{
		SocketClient socket = new SocketClient( connectTimeoutSec );
		socket.connectHard( host, port );
		this.socketClient = socket;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать лог для вывода VRCU и VRAU. Можно null
	 */
	public VRCPClient setLog( ILog log )
	{
		this.log = log;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/***
	 * Разрешается null, чтобы close не закрывал канал.
	 */
	public void setSocketClient( SocketClient socketClient )
	{
		this.socketClient = socketClient;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public SocketClient getSocketClient()
	{
		return socketClient;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public void setReadTimeoutSec( int sec )
	{
		MUST( socketClient != null, "Null SocketClient" );

		try
		{
			socketClient.getSocket().setSoTimeout( sec * 1000 );
		}
		catch( SocketException ex )
		{
			throw new Ex( ex.toString() );
		}
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public int getReadTimeoutSec()
	{
		MUST( socketClient != null, "Null SocketClient" );

		try
		{
			return socketClient.getSocket().getSoTimeout() / 1000;
		}
		catch( SocketException ex )
		{
			throw new Ex( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать новое ограничение на размер ответов, принимаемых с сервера.
	 */
	public void setVrauDataLimit( int newLimit )
	{
		vrauDataLimit = newLimit;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Передача буфера с VRCU и получение ответного VRAU в этот же буфер.
	 * Можно перекрывать в потомках.
	 */
	protected void transmit( Binary buf )
	{
		MUST( socketClient != null, "socketClient not set for VRCPCLient" );

		socketClient.write( buf );

		buf.clear();

		socketClient.read( buf, 16 );
		int vrauSize = buf.getIntBE( 12 );
		MUST( vrauSize >= 0, "Negative VRAU size" );
		MUST( vrauSize <= vrauDataLimit, "Too large answer from server" );

		socketClient.read( buf, vrauSize );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить VRCP-команду, используя для отправки VRCU и получения VRAU заданный сокет.
	 * commandIndex берётся из vrcu.
	 * @return ссылка на vrau.
	 */
	public VRAU command( final VRCU vrcu, VRAU vrau )
	{
		if( (log != null) && !(log instanceof LogDummy) )
		{
			log.writeln( String.format( "VRCU: %08X %08X %08X %s",
				vrcu.index, vrcu.commandCode, vrcu.data.size(), vrcu.data.Hex() ) );
		}

		vrcu.encode( buf );
		transmit( buf );
		MUST( vrau.decode( buf ), "Wrong VRAU syntax" );

		if( (log != null) && !(log instanceof LogDummy) )
		{
			log.writeln( String.format( "VRAU: %08X %08X %08X %08X %s",
				vrau.index, vrau.answerCode, vrau.status, vrau.data.size(), vrau.data.Hex() ) );
		}

		if( vrau.status != VRAU.STATUS_OK )
		{
			THROW( vrau.status, String.format( "(0x%08X) %s", vrau.status, vrau.data.asUTF8() ) );
		}
		return vrau;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * commandIndex - хранится в классе и инкрементируется при отправке команды
	 * @param commandCode - код команды.
	 * @param commandData - данные команды.
	 * @return ссылка на VRAU, хранящийся в объекте. НЕ КОПИЯ.
	 */
	public VRAU command( int commandCode, final Binary commandData )
	{
		++commandIndex;
		vrcu.index = commandIndex;
		vrcu.commandCode = commandCode;
		vrcu.data = commandData;
		return command( vrcu, vrau );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - получить с сервера список поддерживаемых им VRCU-команд.
	 */
	public Arr<Integer> commandEnumCommands()
	{
		Arr<Integer> arr = new Arr<Integer>();

		command( VRCU.ENUM_COMMANDS, Bin() );

		for( int offset = 0; offset < vrau.data.size(); offset +=4 )
		{
			arr.add( vrau.data.getIntBE( offset ) );
		}
		return arr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - остановить сервер.
	 */
	public void commandStopServer()
	{
		command( VRCU.STOP_SERVER, Bin() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void close()
	{
		if( socketClient != null )
			socketClient.close();
	}

}
