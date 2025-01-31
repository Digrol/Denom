// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv;

/**
 * Интерфейс для использования 'словаря' со списком тегов и информацией о них.
 */
public interface ITagDictionary
{
	/**
	 * @return null, если тега нет в словаре.
	 */
	TagInfo find( int tag );

	/**
	 * @return null, если тега нет в словаре.
	 */
	TagInfo find( String name );
}
