// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.sharim;

import org.denom.*;
import org.denom.format.*;
import org.denom.d5.relay.RelayUserClient;

import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
public class SharimRelayUser extends RelayUserClient
{
	/**
	 * Максимальный размер передаваемой части файла.
	 */
	public final static int MAX_FILE_PART = 100000;

	// -----------------------------------------------------------------------------------------------------------------
	public SharimRelayUser( String host, int port )
	{
		super( host, port );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void connectToShare( final Binary resourcePublicKey )
	{
		long resourceHandle = cmdGetResourceInfo( resourcePublicKey ).resourceHandle;
		MUST( resourceHandle != 0, "No Share with Key: " + resourcePublicKey.Hex() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param relativePath - Путь к каталогу относительно корня шары. Корень шары - "".
	 * @return список файлов и каталогов в шаре + relativePath. Без вложенных папок и файлов.
	 * Поля SharimFileInfo.hash могут быть вычислены сервером, но обычно пустые.
	 */
	public Arr<SharimFileInfo> listFiles( String shareName, String relativeDirPath )
	{
		MUST( resourceInfo.resourceHandle != 0, "Not connected to Share" );
		MUST( relaySM != null, "SM not initialized" );

		BinBuilder bb = new BinBuilder();
		bb.append( shareName );
		bb.append( relativeDirPath );
		Binary answer = cmdSendEncrypted( SharimCommand.LIST_FILES, bb.getResult() );

		BinParser bp = new BinParser( answer );
		Arr<SharimFileInfo> arr = new Arr<>();
		bp.getBinableCollection( arr, SharimFileInfo.class );
		return arr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param relativeFilePath - Путь к файлу относительно корня шары.
	 * @return Информация о текущем состоянии файла.
	 * Поле SharimFileInfo.hash обязательно заполняется сервером.
	 */
	public SharimFileInfo getFileInfo( String shareName, String relativeFilePath )
	{
		MUST( resourceInfo.resourceHandle != 0, "Not connected to Share" );
		BinBuilder bb = new BinBuilder();
		bb.append( shareName );
		bb.append( relativeFilePath );
		Binary answer = cmdSendEncrypted( SharimCommand.GET_FILE_INFO, bb.getResult() );

		BinParser bp = new BinParser( answer );
		SharimFileInfo info = (SharimFileInfo)bp.getBinable( SharimFileInfo.class );
		return info;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param relativeFilePath - Путь к файлу относительно корня шары.
	 * @param fileOffset - смещение внутри файла, начиная с которого возвращать байты.
	 * @param filePartSize - Размер считываемой части файла, максимум - MAX_FILE_PART.
	 * @return запрошенная часть файла.
	 */
	public Binary getFilePart( String shareName, String relativeFilePath, long fileOffset, long filePartSize )
	{
		MUST( resourceInfo.resourceHandle != 0, "Not connected to Share" );
		BinBuilder bb = new BinBuilder();
		bb.append( shareName );
		bb.append( relativeFilePath );
		bb.append( fileOffset );
		bb.append( filePartSize );
		Binary answer = cmdSendEncrypted( SharimCommand.GET_FILE_PART, bb.getResult() );

		BinParser bp = new BinParser( answer );
		Binary filePart = bp.getBinary();
		return filePart;
	}

}
