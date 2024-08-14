// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import java.net.InetAddress;
import org.denom.format.JSONObject;

import static org.denom.Ex.*;

/**
 * Настройки ридера смарт-карт.
 */
public class CardReaderOptions
{
	static final String VR_SERVER = "denom.org";
	static final int VR_DEFAULT_PORT = 4256;

	/**
	 * Тип ридера, см. класс ReaderType.
	 */
	public String type = ReaderType.UNKNOWN;

	// ---------------------------------------------------------------------
	/**
	 * Имя PC/SC-ридера.<br>
	 */
	public String pcscName = "";

	// ---------------------------------------------------------------------
	/**
	 * Путь к нативной библиотеке для работы с PC/SC ридерами.
	 * Может быть пустой.
	 */
	public String pcscNativeDll = "";

	// ---------------------------------------------------------------------
	/**
	 * Адрес сервера "Виртуальный Ридер".
	 */
	public String vrHost = VR_SERVER;
	
	/**
	 * Порт сервера "Виртуальный Ридер".
	 */
	public int vrPort = VR_DEFAULT_PORT;
	
	/**
	 * Имя ридера в "Виртуальном Ридере".
	 */
	public String vrName = "";

	/**
	 * Имя клиента, передаваемое при подключении к "Виртуальному Ридеру".
	 */
	public String vrClientName = getHostName();
	
	/**
	 * Пароль для подключения к "Виртуальному Ридеру".
	 */
	public String vrPassword = "";

	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получение имени локального компьютера.
	 * @return - имя локального компьютера или пустая строка, если невозможно получить.
	 */
	private static String getHostName()
	{
		try
		{
			return InetAddress.getLocalHost().getHostName();
		}
		catch( Throwable ex ){}
		return "";
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public CardReaderOptions clone()
	{
		CardReaderOptions opt = new CardReaderOptions();

		opt.type = this.type;

		opt.pcscName = this.pcscName;

		opt.pcscNativeDll = this.pcscNativeDll;

		opt.vrHost = this.vrHost;
		opt.vrPort = this.vrPort;
		opt.vrName = this.vrName;
		opt.vrClientName = this.vrClientName;
		opt.vrPassword = this.vrPassword;

		return opt;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать настройки ридера из JSON-объекта.
	 * @return this.
	 */
	public CardReaderOptions fromJSON( JSONObject jo )
	{
		type = jo.getString( "Reader Type" );

		pcscName      = jo.optString( "PCSC Reader Name" );

		pcscNativeDll = jo.optString( "PCSC Native DLL" );

		vrHost        = jo.optString( "VR Host", VR_SERVER );
		vrPort        = jo.optInt( "VR Port", VR_DEFAULT_PORT );

		vrName        = jo.optString( "VR Reader Name" );
		vrClientName  = jo.optString( "VR Client Name", getHostName() );
		vrPassword    = jo.optString( "VR Password" );
		
		return this;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сохранить настройки в JSON-формате.
	 */
	public JSONObject toJSON()
	{
		JSONObject rOpt = new JSONObject();
		rOpt.put( "Reader Type", type );
		
		rOpt.put( "PCSC Reader Name", pcscName );
		
		rOpt.put( "PCSC Native DLL", pcscNativeDll );

		rOpt.put( "VR Host", vrHost );
		rOpt.put( "VR Port", vrPort );
		
		rOpt.put( "VR Reader Name", vrName );
		rOpt.put( "VR Client Name", vrClientName );
		rOpt.put( "VR Password", vrPassword );
		return rOpt;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает имя ридера, в зависимости от заданного типа ридера.
	 */
	public String getName()
	{
		switch( type )
		{
			case ReaderType.PCSC:       return pcscName;
			case ReaderType.PCSCNative: return pcscName;
			case ReaderType.VR:         return vrName;
			case ReaderType.NULL:       return "Null";
			case ReaderType.UNKNOWN:    return "Unknown";
			default:
				THROW( "Unsupported reader type" );
				return "";
		}
	}

}