// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.format;

import java.util.Arrays;
import java.util.Collection;

import org.denom.*;

import static org.denom.Ex.*;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Helps to parse Binary array according to 'Denom Structured Data Standard'.
 */
public class BinParser
{
	private Binary bin;
	private int offset;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param bin - Array with serialized data. Not copied.
	 */
	public BinParser( final Binary bin, int offset )
	{
		this.bin = bin;
		this.offset = offset;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public BinParser( final Binary bin )
	{
		this( bin, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public int getOffset()
	{
		return offset;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void reset( final Binary bin, int offset )
	{
		this.bin = bin;
		this.offset = offset;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean getBoolean()
	{
		boolean res = bin.get( offset ) != 0;
		++offset;
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public int getInt()
	{
		int res = bin.getIntBE( offset );
		offset += 4;
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public long getLong()
	{
		long res = bin.getLong( offset );
		offset += 8;
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить сериализованный массив байтов - byte[].
	 */
	public byte[] getByteArr()
	{
		int size = bin.getIntBE( offset );
		offset += 4;
		byte[] res = Arrays.copyOfRange( bin.getDataRef(), offset, offset + size );
		offset += size;
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить сериализованную строку - String.
	 */
	public String getString()
	{
		int size = bin.getIntBE( offset );
		offset += 4;
		String res = new String( bin.getDataRef(), offset, size, Strings.UTF8 );
		offset += size;
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить сериализованный массив c объектами String.
	 */
	public String[] getStringArr()
	{
		int arrLen = bin.getIntBE( offset );
		offset += 4;
		String[] arr = new String[ arrLen ];
		for( int i = 0; i < arrLen; ++i )
			arr[ i ] = getString();

		return arr;
	}


	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить сериализованный массив c объектами String.
	 */
	public Collection<String> getStringCollection( Collection<String> collection )
	{
		int arrLen = bin.getIntBE( offset );
		offset += 4;
		
		for( int i = 0; i < arrLen; ++i )
			collection.add( getString() );

		return collection;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить сериализованный Binary.
	 */
	public Binary getBinary()
	{
		int size = bin.getIntBE( offset );
		MUST( size >= 0, "Negative len while parsing Binable object" );

		offset += 4;
		Binary res = bin.slice( offset, size );
		offset += size;
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить сериализованный Binary.
	 * @param maxLen - максимально допустимая длина.
	 * @return
	 */
	public Binary getBinary( int maxLen )
	{
		int size = bin.getIntBE( offset );
		MUST( (size >= 0), "Negative len while parsing Binable object" );
		MUST( size <= maxLen, "Binable: Incorrect Binary length" );

		offset += 4;
		Binary res = bin.slice( offset, size );
		offset += size;
		return res; 
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить сериализованный массив c объектами Binary.
	 */
	public Binary[] getBinaryArr()
	{
		int arrLen = bin.getIntBE( offset );
		offset += 4;
		Binary[] arr = new Binary[ arrLen ];
		for( int i = 0; i < arrLen; ++i )
			arr[ i ] = getBinary();

		return arr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить сериализованный массив c объектами Binary.
	 */
	public Collection<Binary> getBinaryCollection( Collection<Binary> collection )
	{
		int arrLen = bin.getIntBE( offset );
		offset += 4;
		
		for( int i = 0; i < arrLen; ++i )
			collection.add( getBinary() );

		return collection;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить вложенный сериализованный объект, реализующий интерфейс IBinable.
	 */
	public IBinable getBinable( Class<? extends IBinable> clazz )
	{
		IBinable instance = null;

		try
		{
			int size = bin.getIntBE( offset );
			offset += 4;

			instance = clazz.getDeclaredConstructor().newInstance();
			instance.fromBin( bin, offset );
			offset += size;
		}
		catch( Exception ex )
		{
			THROW( ex.toString() );
		}

		return instance;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить массив объектов, реализующих интерфейс IBinable.
	 */
	@SuppressWarnings("unchecked")
	public IBinable[] getBinableArr( Class<? extends IBinable []> clazz )
	{
		IBinable[] arr = null;
		Class<?> componentType = clazz.getComponentType();
		
		try
		{
			int arrLen = bin.getIntBE( offset );
			offset += 4;
			arr = (IBinable[])java.lang.reflect.Array.newInstance( componentType, arrLen );
			
			for( int i = 0; i < arr.length; ++i )
			{
				arr[ i ] = getBinable( (Class<? extends IBinable>)componentType );
			}
		}
		catch( Exception ex )
		{
			THROW( ex.toString() );
		}

		return arr;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить коллекцию объектов, реализующих интерфейс IBinable.
	 */
	@SuppressWarnings("unchecked")
	public Collection<? extends IBinable> getBinableCollection( Collection<? extends IBinable> collection, 
			Class<? extends IBinable> elemType )
	{
		int arrLen = bin.getIntBE( offset );
		offset += 4;
		
		for( int i = 0; i < arrLen; ++i )
			((Collection<IBinable>)collection).add( getBinable( elemType ) );

		return collection;
	}

}
