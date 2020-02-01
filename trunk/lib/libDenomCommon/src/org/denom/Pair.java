// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom;

/**
 * Пара из двух аргументов.
 * Чтобы для хранения этих двух аргументов в массиве не делать новый класс.
 * Названия key и value - условны.
 */
public class Pair<K, V>
{
	public K key;
	public V value;

	// -----------------------------------------------------------------------------------------------------------------
	public Pair( K key, V value )
	{
		this.key = key;
		this.value = value;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static <K, V> Pair<K, V> of( K key, V value )
	{
		return new Pair<K, V>( key, value );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String toString()
	{
		return key + " = " + value;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int hashCode()
	{
		return key.hashCode() * 13 + (value == null ? 0 : value.hashCode());
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public boolean equals( Object o )
	{
		if( this == o )
			return true;
		
		if( o instanceof Pair<?, ?> )
		{
			Pair<?, ?> pair = (Pair<?, ?>)o;
			if( (key != null) ? !key.equals( pair.key ) : pair.key != null )
				return false;
			if( value != null ? !value.equals( pair.value ) : pair.value != null )
				return false;
			return true;
		}
		return false;
	}

}