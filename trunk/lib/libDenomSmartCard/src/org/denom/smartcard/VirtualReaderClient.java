// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.*;
import org.denom.net.SocketClient;
import org.denom.vrcp.*;

import static org.denom.format.LV.*;
import static org.denom.Binary.*;
import static org.denom.Ex.*;

/**
 * Клиент для сервера виртуальных ридеров.
 */
public class VirtualReaderClient extends VRCPClient
{
	/**
	 * Коды команд (Command Codes)
	 */
	public final static int ENUM_READERS       = 0xC0000002;
	public final static int CONNECT            = 0xC0000003;
	public final static int DISCONNECT         = 0xC0000004;
	public final static int IS_CARD_PRESENT    = 0xC0000005;
	public final static int POWER_ON           = 0xC0000006;
	public final static int POWER_OFF          = 0xC0000007;
	public final static int RESET              = 0xC0000008;
	public final static int CMD                = 0xC0000009;
	public final static int WAIT_CARD_PRESENT  = 0xC0000010;
	public final static int WAIT_CARD_REMOVE   = 0xC0000011;

	public final static int ATTACH_READER      = 0xC0000021;
	public final static int REMOVE_READER      = 0xC0000022;
	public final static int CREATE_READER      = 0xC0000023;

	
	/**
	 * Буфер для формирования данных команды.
	 */
	private Binary dataBuf = new Binary().reserve( 512 );

	// -----------------------------------------------------------------------------------------------------------------
	public VirtualReaderClient() {}

	// -----------------------------------------------------------------------------------------------------------------
	public VirtualReaderClient( SocketClient socketClient )
	{
		super( socketClient );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public VirtualReaderClient( String host, int port )
	{
		this( host, port, 10 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструкор для краткости создания объекта в простых случаях.
	 */
	public VirtualReaderClient( String host, int port, int connectTimeoutSec )
	{
		super( host, port, connectTimeoutSec );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - Получить список ридеров в VR-сервере.
	 */
	public String[] commandEnumReaders()
	{
		command( ENUM_READERS, Bin() );
		return parseLV4Strings( vrau.data );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - Создать новую модель карты в VR-сервере.
	 */
	public void commandCreateModel( String modelName, String connectPassword, String removePassword,
			Binary cardID, Binary isdAID,
			Binary sdKeyEnc, Binary sdKeyMac, Binary sdKeyDek )
	{
		MUST( (cardID.size() == 8) && (isdAID.size() >= 5) && (isdAID.size() <= 16)
				&& (sdKeyEnc.size() == 16) && (sdKeyMac.size() == 16) && (sdKeyDek.size() == 16), "Wrong card model params" );
		
		String[] arr = new String[ 4 ];
		arr[ 0 ] = modelName;
		arr[ 1 ] = connectPassword;
		arr[ 2 ] = removePassword;
		arr[ 3 ] = Bin( cardID, sdKeyEnc, sdKeyMac, sdKeyDek, isdAID ).Hex();

		command( CREATE_READER, LV4Strings( arr ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду удаления модели с сервера.
	 */
	public void commandRemoveModel( String modelName, String removePassword )
	{
		command( REMOVE_READER, LV4Strings( modelName, removePassword ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - подключиться к ридеру с заданным именем.
	 * @param clientName - имя подключающегося клиента.
	 * @param password - пароль доступа к удалённому ридеру.
	 * @return - Handle ридера;
	 */
	public int commandConnect( String clientName, String readerName, String password )
	{
		command( CONNECT, LV4Strings( clientName, readerName, password ) );
		MUST( vrau.data.size() == 4, "Wrong answer in VR command CONNECT" );
		return (int)vrau.data.asU32();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - отключиться от ридера readerHandle.
	 */
	public void commandDisconnect( int readerHandle )
	{
		dataBuf.clear();
		dataBuf.addInt( readerHandle );
		command( DISCONNECT, dataBuf );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - Is Card Present для ридера readerHandle.
	 */
	public boolean commandIsCardPresent( int readerHandle )
	{
		dataBuf.clear();
		dataBuf.addInt( readerHandle );
		command( IS_CARD_PRESENT, dataBuf );
		MUST( vrau.data.size() == 1, "Wrong answer in VR command IS CARD PRESENT" );
		return vrau.data.get( 0 ) != 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - Wait Card Present для ридера readerHandle.
	 */
	public boolean commandWaitCardPresent( int readerHandle, int timeoutSec )
	{
		dataBuf.clear();
		dataBuf.addInt( readerHandle );
		dataBuf.addInt( timeoutSec );
		command( WAIT_CARD_PRESENT, dataBuf );
		MUST( vrau.data.size() == 1, "Wrong answer in VR command WAIT CARD PRESENT" );
		return vrau.data.get( 0 ) != 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - Wait Card Remove для ридера readerHandle.
	 */
	public boolean commandWaitCardRemove( int readerHandle, int timeoutSec )
	{
		dataBuf.clear();
		dataBuf.addInt( readerHandle );
		dataBuf.addInt( timeoutSec );
		command( WAIT_CARD_REMOVE, dataBuf );
		MUST( vrau.data.size() == 1, "Wrong answer in VR command WAIT CARD REMOVE" );
		return vrau.data.get( 0 ) != 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - Power On для ридера readerHandle.
	 */
	public Binary commandPowerOn( int readerHandle )
	{
		dataBuf.clear();
		dataBuf.addInt( readerHandle );
		command( POWER_ON, dataBuf );
		return vrau.data.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - Power Off для ридера readerHandle.
	 */
	public void commandPowerOff( int readerHandle )
	{
		dataBuf.clear();
		dataBuf.addInt( readerHandle );
		command( POWER_OFF, dataBuf );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - Reset для ридера readerHandle.
	 */
	public Binary commandReset( int readerHandle )
	{
		dataBuf.clear();
		dataBuf.addInt( readerHandle );
		command( RESET, dataBuf );
		return vrau.data.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить команду - передать CApdu ридеру readerHandle.
	 */
	public RApdu commandCmd( int readerHandle, final CApdu capdu )
	{
		dataBuf.clear();
		dataBuf.addInt( readerHandle );
		dataBuf.add( capdu.toBin() );

		command( CMD, dataBuf );
		return new RApdu( vrau.data );
	}
}
