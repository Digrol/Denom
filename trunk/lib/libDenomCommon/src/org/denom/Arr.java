// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom;

import java.util.*;
import java.util.function.Predicate;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Массив с обращением к элементам через предикаты.
 * 
 * Пример использования: <pre>
 * 
 * static class Key
 * {
 *     String id = "";
 *     Binary body = new Binary();
 * 
 *     public String getId()
 *     {
 *         return id;
 *     }
 * 
 *     public String toString()
 *     {
 *         return "id: " + id + "; body: " + body.Hex();
 *     }
 * }
 * 
 * Arr<Key> keys = new Arr<Key>();
 * 
 * // 1. Проверить, содержится ли в массиве искомый элемент.
 * keys.contains( key -> key.id.equals( "6" ) )
 * 
 * // 2. Получить ссылку на элемент, удовлетворяющий предикату.
 * Key aKey = keys.getIf( k -> k.id.equals("6") );
 * 
 * // 3. Удалить элемент, удовлетворяющий предикату.
 * keys.removeIf( k -> k.id.equals("5") );
 * 
 * // 4. Для каждого элемента выполнить заданный код.
 * keys.forEach( k -> System.out.println( k ) );
 * 
 * // 5. Сортировка элементов в обратном и прямом порядке, разные примеры синтаксиса.
 * keys.sort( Comparator.comparing( Key::getId ).reversed() );
 * keys.sort( (l, r) -> l.id.compareTo( r.id ) );
 * </pre>
 */
public class Arr<E> extends ArrayList<E>
{
	private static final long serialVersionUID = 86444582390892189L;

	// -----------------------------------------------------------------------------------------------------------------
	public Arr() {}

	// -----------------------------------------------------------------------------------------------------------------
	public Arr( int initialCapacity )
	{
		super( initialCapacity );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Arr( Collection<? extends E> c )
	{
		super( c );
	}


	// -----------------------------------------------------------------------------------------------------------------
	public boolean contains( Predicate<? super E> filter )
	{
		return getIf( filter ) != null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * null - если не найден.
	 */
	public E getIf( Predicate<? super E> filter )
	{
		Objects.requireNonNull( filter );
		for( E e : this )
		{
			if( filter.test( e ) )
				return e;
		}
		return null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Исключение, если элемент не найден.
	 */
	public E get( Predicate<? super E> filter )
	{
		E e = getIf( filter );
		Ex.MUST( e != null, "Element not found in collection" );
		return e;
	}

}
