// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

/**
 * Что карта должна вернуть в ответе на команду SELECT.
 */
public final class SelectAnswer
{
	public static final int FCI      = 0x00;
	public static final int FCP      = 0x04;
	public static final int FMD      = 0x08;
	public static final int NOTHING  = 0x0C;  // ничего не возвращать или проприетарный ответ
}
