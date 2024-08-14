// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt;

import org.denom.*;
import static org.denom.Ex.*;

/**
 * Утилиты для криптографических классов.
 */
public final class Crypt
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выровнять данные до длины, кратной размеру блока.
	 * Модифицируется входной массив.
	 * @param data - Входные данные.
	 * @param blockSize - Размер блока.
	 * @param alignMode - Режим выравнивания.
	 */
	public static void pad( Binary data, int blockSize, AlignMode alignMode )
	{
		switch( alignMode )
		{
			case NONE:
				break;

			case BLOCK:
				MUST( blockSize > 0, "Размер блока должен быть > 0." );
				int padLen = blockSize - (data.size() & (blockSize - 1));
				data.reserve( data.size() + padLen );
				data.add( 0x80 );
				--padLen;
				for( int i = 0; i < padLen; ++i )
				{
					data.add( 0x00 );
				}
				break;

			default:
				THROW( "Wrong data alignment" );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Убрать выравнивание.
	 * Модифицируется входной массив.
	 * @param data - Входной Binary.
	 * @param alignMode - Режим выравнивания.
	 */
	public static void unPad( Binary data, int blockSize, AlignMode alignMode )
	{
		switch( alignMode )
		{
			case NONE:
				break;

			case BLOCK:
				MUST( blockSize > 0, "Размер блока должен быть > 0." );
				MUST( !data.empty(), "Нет данных для снятия выравнивания." );
				MUST( (data.size() & (blockSize - 1)) == 0, 
					"Длина данных для снятия выравнивания должна быть кратна размеру блока." );
				
				int i = data.size();
				do
				{
					--i;
				}
				while( (i > 0) && (data.get( i ) == 0x00) );
				
				MUST( (data.get( i ) == 0x80) && ((data.size() - i) <= blockSize), "Ошибка снятия выравнивания." );
				
				data.resize( i );
				break;

			default:
				THROW( "Wrong data alignment" );
		}
	}

}
