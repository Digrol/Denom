// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt;

/**
 * Режимы генерации криптографической контрольной суммы.
 */
public enum CCSMode
{
	/**
	 * Классический алгоритм: для ГОСТ - стандартная имитовставка,<br>
	 * для остальных - CBC - ISO 9797-1, algorithm 1.
	 */
	CLASSIC,

	/**
	 * ISO 9797-1, algorithm 3: Для всех алгоритмов, кроме TripleDES, тоже самое, что и CCS_CLASSIC.<br>
	 * для TripleDES - шифрование всех блоков, кроме последнего, DES-CBC на 1-ой половине ключа,<br>
	 * последний блок шифруется TripleDES.
	 */
	FAST
}
