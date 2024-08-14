// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.vrcp;

import org.denom.*;

/**
 * Коды ошибок по протоколу VRCP.
 * Класс можно бросать для генерации исключений при парсинге VRCU.
 */
public class VRCPError extends RuntimeException
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Коды ошибок, определённые в VRCP
	 */
	public final static int COMMAND_NOT_SUPPORTED = 0xE0000001;
	public final static int WRONG_VRCU_SYNTAX     = 0xE0000002;
	public final static int WRONG_COMMAND_DATA    = 0xE0000003;
	public final static int READER_NOT_FOUND      = 0xE0000004;
	public final static int READER_IS_BUSY        = 0xE0000005;
	public final static int WRONG_HANDLE          = 0xE0000006;
	public final static int NO_CARD_IN_READER     = 0xE0000007;
	public final static int WRONG_PASSWORD        = 0xE0000008;
	public final static int READER_NAME_IS_BUSY   = 0xE0000009;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Ошибки, специфичные для конкретной реализации, должны начинаться с этого номера.
	 */
	public final static int IMPL_SPECIFIC         = 0xEE000000;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Ошибка, для которой есть описание, но код не задан.
	 */
	public final static int NO_CODE = 0xFFFFFFFF;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор для ошибок, определённых в протоколе VRCP.
	 */
	public VRCPError( int code )
	{
		mCode = code;
		mMessage = getErrorDescription( code );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор для ошибок, код которых не задан.
	 */
	public VRCPError( String msg )
	{
		mCode = VRCPError.NO_CODE;
		mMessage = msg;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор для IMPL_SPECIFIC ошибок.
	 */
	public VRCPError( int code, String msg )
	{
		mCode = code;
		mMessage = msg;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public int getCode()
	{
		return mCode;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String getMessage()
	{
		return mMessage;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static String getErrorDescription( int code )
	{
		switch( code )
		{
			case VRCPError.COMMAND_NOT_SUPPORTED: return "{VRCP ERROR} Command not supported";
			case VRCPError.WRONG_VRCU_SYNTAX    : return "{VRCP ERROR} Wrong VRCU syntax";
			case VRCPError.WRONG_COMMAND_DATA   : return "{VRCP ERROR} Wrong Command data";
			case VRCPError.READER_NOT_FOUND     : return "{VRCP ERROR} Reader not found";
			case VRCPError.READER_IS_BUSY       : return "{VRCP ERROR} Reader is busy";
			case VRCPError.WRONG_HANDLE         : return "{VRCP ERROR} Wrong Handle";
			case VRCPError.NO_CARD_IN_READER    : return "{VRCP ERROR} No card in reader";
			case VRCPError.WRONG_PASSWORD       : return "{VRCP ERROR} Wrong Password";
			case VRCPError.READER_NAME_IS_BUSY  : return "{VRCP ERROR} Reader Name is busy";
			default: Ex.THROW( "Wrong VRCP error code" );
		}
		return ""; // Antiwarning
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * MUST для ошибок, определённых в протоколе VRCP.
	 */
	public static void MUST( boolean expression, int code )
	{
		if( !expression )
			throw new VRCPError( code );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * MUST для ошибок, код которых не задан.
	 */
	public static void MUST( boolean expression, String msg )
	{
		if( !expression )
			throw new VRCPError( msg );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * MUST для IMPL_SPECIFIC ошибок.
	 */
	public static void MUST( boolean expression, int code, String msg )
	{
		if( !expression )
			throw new VRCPError( code, msg );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private int mCode;
	private String mMessage;

	private static final long serialVersionUID = 1L;
}
