// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.*;
import org.denom.log.ILog;


/**
 * Клиент для сервера "Виртуальный ридер", транспорт - сокет.
 */
public class CardReaderVRSocket extends CardReader
{
	protected int readerHandle = 0;
	protected String readerName = "";

	protected boolean isPowered = false;
	protected boolean isConnectedToReader = false;

	protected VirtualReaderClient vrClient = new VirtualReaderClient();

	// -----------------------------------------------------------------------------------------------------------------
	public CardReaderVRSocket() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подключиться к Виртуальному Ридеру (открытие клиентского сокета).
	 * @param vrHost - URL Виртуального Ридера.
	 * @param vrPort - порт
	 * @return - ссылка на себя
	 */
	public CardReaderVRSocket connectToVR( String vrHost, int vrPort )
	{
		return connectToVR( vrHost, vrPort, 10 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подключиться к Виртуальному Ридеру (открытие клиентского сокета).
	 * @param vrHost - URL Виртуального Ридера.
	 * @param vrPort - порт.
	 * @param connectTimeoutSec - таймаут на подключение.
	 * @return - ссылка на себя.
	 */
	public CardReaderVRSocket connectToVR( String vrHost, int vrPort, int connectTimeoutSec )
	{
		disconnectFromVR();
		vrClient = new VirtualReaderClient( vrHost, vrPort, connectTimeoutSec );

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void disconnectFromVR()
	{
		disconnect();

		vrClient.close();
		vrClient = new VirtualReaderClient();
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public void setReadTimeoutSec( int sec )
	{
		vrClient.setReadTimeoutSec( sec );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public int getReadTimeoutSec()
	{
		return vrClient.getReadTimeoutSec();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает список команд, поддерживаемых Виртуальным Ридером.
	 */
	public Arr<Integer> enumCommands()
	{
		return vrClient.commandEnumCommands();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String[] enumReaders()
	{
		return vrClient.commandEnumReaders();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подключиться к ридеру по имени.
	 * @param readerName - Имя ридера, с которым будет вестись работа.
	 */
	@Override
	public CardReader connect( String readerName )
	{
		return connect( "John Doe", readerName, "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подключиться к ридеру по имени, указав пароль и имя подключаемого клиента.
	 * @param readerName - Имя ридера, с которым будет вестись работа.
	 */
	public CardReader connect( String clientName, String readerName, String password )
	{
		disconnect();
		readerHandle = vrClient.commandConnect( clientName, readerName, password );
		this.readerName = readerName;
		isConnectedToReader = true;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Отключиться от ридера.
	 */
	@Override
	public void disconnect()
	{
		if( !isConnectedToReader )
			return;

		powerOffImpl();
		try
		{
			vrClient.commandDisconnect( readerHandle );
		}
		catch( Throwable ex ) {}

		readerHandle = 0;
		readerName = "";
		isConnectedToReader = false;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public boolean isCardPresent()
	{
		return vrClient.commandIsCardPresent( readerHandle );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public boolean waitCardPresent( int timeoutSec )
	{
		return vrClient.commandWaitCardPresent( readerHandle, timeoutSec );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public boolean waitCardRemove( int timeoutSec )
	{
		return vrClient.commandWaitCardRemove( readerHandle, timeoutSec );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected Binary powerOnImpl()
	{
		powerOff();
		Binary atr = vrClient.commandPowerOn( readerHandle );
		isPowered = true;
		return atr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected void powerOffImpl()
	{
		if( !isPowered )
			return;

		try
		{
			vrClient.commandPowerOff( readerHandle );
		}
		catch( Throwable ex ) {}

		isPowered = false;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected Binary resetImpl()
	{
		return vrClient.commandReset( readerHandle );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить имя активного ридера.
	 */
	@Override
	public String getName()
	{
		return readerName;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public RApdu transmit( CApdu capdu )
	{
		return vrClient.commandCmd( readerHandle, capdu );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public CardReaderChannel getCardChannel( int logicalChannel )
	{
		return new CardReaderChannel( this, logicalChannel );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public CardReader setTransportLog( ILog log )
	{
		super.setTransportLog( log );
		vrClient.setLog( log );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void close()
	{
		disconnectFromVR();
	}
}
