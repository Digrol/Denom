// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.freemem;

import org.denom.smartcard.CApdu;
import static org.denom.Binary.*;

/**
 * Формирование CApdu для апплета FreeMem.
 */
public class ApduFreeMem
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить количество свободной памяти в карте.
	 * В ответ возвращается 6 байт: FreeEE | FreeRTR | FreeDTR.
	 */
	public static CApdu GetFreeMem()
	{
		return new CApdu( 0x80, 0x01, 0x00, 0x00, Bin(), CApdu.MAX_NE, "{FreeMem} GET FREE MEM" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выделить память в EEPROM
	 * @param numBytes - количество байт для выделения
	 */
	public static CApdu AllocEE( int numBytes )
	{
		return new CApdu( 0x80, 0xAA, 0x00, 0x00, Num_Bin( numBytes, 2 ), 0, "{FreeMem} ALLOC MEM" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызвать Garbage Collector (освобождение памяти, выделенной командами {@link #AllocEE(int)})
	 */
	public static CApdu RunGC()
	{
		return new CApdu( 0x80, 0xBB, 0x00, 0x00, Bin(), 0, "{FreeMem} RUN GC" );
	}

}
