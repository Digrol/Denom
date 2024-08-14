// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.vrcp;

import org.denom.*;

/**
 * Формирование и разбор Command Unit для VRCP.
 * Ограничение класса: длина данных не может быть больше 2^31-1 (максимальный положительный int).
 */
public class VRCU
{
	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Коды команд (Command Codes)
	 */
	public final static int ENUM_COMMANDS      = 0xC0000001;
	public final static int STOP_SERVER        = 0xC0FFFFFF;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Порядковый номер команды
	 */
	public int index;

	/**
	 * Код команды
	 */
	public int commandCode;

	/**
	 * Данные команды. Поля Length нет в виде переменной, т.к. Length = data.size()
	 */
	public Binary data = new Binary();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор по умолчанию. Все поля - нулевые (пустые).
	 */
	public VRCU() {}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор, все поля передаются в параметрах.
	 * @param index - Порядковый номер команды.
	 * @param commandCode - Код команды.
	 * @param data - Данные команды.
	 */
	public VRCU( int index, int commandCode, final Binary data )
	{
		this.index = index;
		this.commandCode = commandCode;
		this.data = data.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Разобрать байтовый массив по полям, согласно синтаксису протокола VRCP.
	 * Выполняется на стороне Виртуального ридера.
	 * @param bin - байтовый массив.
	 * @return - true при успешном декодировании, false - синтаксис VRCU нарушен.
	 */
	public boolean decode( final Binary bin )
	{
		this.data.clear();

		int size = bin.size();

		if( size < 12 )
		{
			return false;
		}

		this.index = bin.getIntBE( 0 );
		this.commandCode = bin.getIntBE( 4 );

		int length = bin.getIntBE( 8 );
		if( (length != (size - 12)) )
		{
			return false;
		}

		if( length != 0 )
		{
			this.data.assign( bin, 12, length );
		}
		
		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сформировать байтовый массив для передачи Виртуальному ридеру.
	 * this.data должен быть не более 2^31-1-12 байт.
	 * @param bin - VRCU в виде массива байтов (выходной массив).
	 */
	public void encode( Binary bin )
	{
		encode( this.index, this.commandCode, this.data, bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сформировать байтовый массив для передачи Виртуальному ридеру.
	 * @param bin - VRCU в виде массива байтов.
	 */
	public static void encode( int index, int commandCode, final Binary data, Binary bin )
	{
		bin.clear();
		int length = data.size();
		bin.resize( 12 + length );
		bin.setInt( 0, index );
		bin.setInt( 4, commandCode );
		bin.setInt( 8, length );
		bin.set( 12, data, 0, length );
	}
}