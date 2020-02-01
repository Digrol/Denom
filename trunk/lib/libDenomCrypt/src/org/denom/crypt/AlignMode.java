// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt;

/**
 * Modes for data align in block ciphers.
 */
public enum AlignMode
{
	/**
	 * Data not aligned
	 */
	NONE,

	/**
	 * Выравнивание до длины блока 8000...00
	 */
	BLOCK
}