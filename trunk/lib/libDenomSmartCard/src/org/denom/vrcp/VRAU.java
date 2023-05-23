// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.vrcp;

import org.denom.*;
import static org.denom.Ex.*;

/**
 * Формирование и разбор Answer Unit для VRCP.
 * Ограничение класса: длина данных не может быть больше 2^31-1 (максимальный положительный int).
 */
public class VRAU
{
	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Коды ответов (Answer Codes)
	 */
	public final static int ENUM_COMMANDS      = 0xA0000001;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Значение поля status при успешном выполнении VRCU
	 */
	public final static int STATUS_OK = 0x00000000;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Порядковый номер команды.
	 */
	public int index;

	/**
	 * Код ответа.
	 */
	public int answerCode;

	/**
	 * Статус выполнения команды.
	 */
	public int status;

	/**
	 * Данные ответа. Поля Length нет в виде переменной, т.к. Length = data.size()
	 */
	public Binary data = new Binary();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор по умолчанию. Все поля - нулевые.
	 */
	public VRAU() {}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * 
	 * @param index - Порядковый номер команды.
	 * @param answerCode - Код ответа.
	 * @param status
	 * @param data
	 */
	public VRAU( int index, int answerCode, int status, final Binary data )
	{
		this.index = index;
		this.answerCode = answerCode;
		this.status = status;
		this.data = data.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Разобрать байтовый массив по полям, согласно синтаксису протокола VRCP.
	 * Выполняется на стороне Терминала.
	 * @param vrau - байтовый массив.
	 * @return - true при успешном декодировании, false - синтаксис VRAU нарушен.
	 */
	public boolean decode( final Binary vrau )
	{
		this.data.clear();
		int size = vrau.size();

		if( size < 16 )
		{
			return false;
		}

		this.index = vrau.getIntBE( 0 );
		this.answerCode = vrau.getIntBE( 4 );
		this.status = vrau.getIntBE( 8 );
		
		int length = vrau.getIntBE( 12 );
		if( (length != (size - 16)) )
		{
			return false;
		}

		if( length != 0 )
		{
			this.data = vrau.slice( 16, length );
		}
		
		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сформировать байтовый массив для передачи Терминалу.
	 * this.data должен быть не более 2^31-1-16 байт.
	 * @param vrau - VRAU в виде массива байтов (выходной массив).
	 */
	public void encode( Binary vrau )
	{
		encode( index, answerCode, status, data, vrau );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сформировать байтовый массив для передачи Терминалу.
	 * @param vrau - VRAU в виде массива байтов.
	 */
	public static void encode( int index, int answerCode, int status, final Binary data, Binary vrau )
	{
		vrau.clear();
		int length = data.size();
		vrau.resize( 16 + length );
		vrau.setInt( 0, index );
		vrau.setInt( 4, answerCode );
		vrau.setInt( 8, status );
		vrau.setInt( 12, length );
		vrau.set( 16, data, 0, length );
	}

	// =================================================================================================================
	// Парсинг ответных VRAU для некоторых команд.
	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Разбор ответа на команду ENUM COMMANDS.
	 * @return - список команд, поддерживаемых Виртуальным Ридером.
	 */
	public int[] parseEnumCommands()
	{
		MUST( answerCode == VRAU.ENUM_COMMANDS, "Wrong VR Answer Code in ENUM COMMANDS" );
		MUST( data.size() % 4 == 0, "Incorrect answer in VR command ENUM COMMANDS");

		int[] cmdList = new int[ data.size() >> 2 ];
		int offset = 0;
		int i = 0;
		while( offset < data.size() )
		{
			cmdList[ i ] = data.getIntBE( offset );
			offset += 4;
			++i;
		}
		return cmdList;
	}
}
