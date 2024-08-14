// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.format;

import java.util.Collection;

import org.denom.*;

/**
 * Helps serialize data according to "Denom Structured Data Standard".
 */
public class BinBuilder
{
	private Binary result;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param bin - ссылка на массив, в который будут добавляться сериализованные данные.
	 */
	public BinBuilder( final Binary bin )
	{
		this.result = bin;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализованные данные накапливаются в новом Binary.
	 * Ссылку на него можно получить методом getResult.
	 */
	public BinBuilder()
	{
		this( new Binary() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает сссылку на массив с сериализованными данными.
	 */
	public Binary getResult()
	{
		return result;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать boolean.
	 */
	public BinBuilder append( boolean flag )
	{
		result.add( flag ? 1 : 0 );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать int.
	 */
	public BinBuilder append( int i )
	{
		result.addInt( i );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать long.
	 */
	public BinBuilder append( long l )
	{
		result.addLong( l );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать Binary.
	 */
	public BinBuilder append( final Binary b )
	{
		result.addInt( b.size() );
		result.add( b );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать Binary.
	 */
	public BinBuilder append( final Binary b, int offset, int length )
	{
		result.addInt( length );
		result.add( b, offset, length );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать Binary[].
	 */
	public BinBuilder append( final Binary[] arr )
	{
		result.addInt( arr.length );
		for( Binary b : arr )
		{
			append( b );
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать коллекцию Binary.
	 */
	public BinBuilder appendBinaryCollection( final Collection<Binary> collection )
	{
		result.addInt( collection.size() );
		for( Binary b : collection )
		{
			append( b );
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать byte[].
	 */
	public BinBuilder append( final byte[] arr )
	{
		result.addInt( arr.length );
		result.add( arr );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать String.
	 */
	public BinBuilder append( final String s )
	{
		byte[] arr = s.getBytes( Strings.UTF8 );
		result.addInt( arr.length );
		result.add( arr );
		return this;
	}


	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать коллекцию String.
	 */
	public BinBuilder appendStringCollection( final Collection<String> collection )
	{
		result.addInt( collection.size() );
		for( String str : collection )
		{
			append( str );
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать IBinable объект.
	 */
	public BinBuilder append( final IBinable binable )
	{
		return append( binable.toBin() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать массив IBinable объектов.
	 */
	public BinBuilder append( final IBinable[] binableArray )
	{
		result.addInt( binableArray.length );
		for( IBinable b : binableArray )
		{
			append( b );
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать коллекцию IBinable объектов.
	 */
	public BinBuilder append( final Collection<? extends IBinable> collection )
	{
		result.addInt( collection.size() );
		for( IBinable b : collection )
		{
			append( b.toBin() );
		}
		return this;
	}

}
