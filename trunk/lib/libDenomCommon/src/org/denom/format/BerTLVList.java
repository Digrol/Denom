// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.format;

import java.util.ArrayList;
import java.util.Arrays;

import org.denom.*;

import static org.denom.Binary.Bin;
import static org.denom.format.BerTLV.*;

/**
 * Список BER-TLV.
 */
public class BerTLVList
{
	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Список BER-TLV записей. Заполняется при создании экземпляра. Может быть пустым.
	 */
	public final ArrayList<BerTLV> recs;

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Создать парсер для разбора BerTLV.
	 * @param bin - список/конкатенация BerTLV-записей.
	 */
	public BerTLVList( final Binary bin )
	{
		recs = new ArrayList<BerTLV>();
		assign( bin );
	}

	// ---------------------------------------------------------------------------------------------------------------------
	public BerTLVList( String hexStr )
	{
		this( Bin(hexStr) );
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Аналог конструктора. Заполняет поля bin и recs.
	 * @return Ссылка на себя.
	 */
	public BerTLVList assign( final Binary bin )
	{
		Ex.MUST( isTLVList( bin ), "Ошибка парсинга BER-TLV-записи" );

		recs.clear();

		Int offset = new Int( 0 );
		BerTLV rec = new BerTLV();
		while( (offset.val < bin.size()) && BerTLV.parseTLV( bin, offset, rec ) )
		{
			recs.add( rec.clone() );
		}
		return this;
	}

	// ---------------------------------------------------------------------------------------------------------------------
	public void assign( String hexStr )
	{
		assign( Bin( hexStr ) );
	}
	
	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Найти в списке запись с заданным тегом Tag.<br>
	 * В списке может быть несколько записей с тегом Tag.
	 * @param Tag - Тег записи.
	 * @param nth - Какая по счёту запись нужна (считаем от 1).
	 * @return Искомая запись, или пустой объект BerTLV, если запись не найдена.
	 */
	public BerTLV find( int Tag, int nth )
	{
		int k = 0;

		for( int i = 0; i < recs.size(); ++i )
		{
			if( recs.get( i ).tag == Tag )
			{
				if( ++k == nth )
				{
					return recs.get( i );
				}
			}
		}
		return new BerTLV();
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Найти в списке первую запись с заданным тегом Tag.
	 * @param Tag - Тег записи.
	 * @return Искомая запись, или пустой объект BerTLV если запись не найдена.
	 */
	public BerTLV find( int Tag )
	{
		return find( Tag, 1 );
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Найти в списке запись по заданному пути.
	 * 
	 * @param path
	 *            Путь - это теги, разделённые слешем. Пример - "6F / 84".
	 * @return Искомая запись, или пустой объект BerTLV если запись не найдена.
	 */
	public BerTLV find( String path )
	{
		String[] tags = path.replaceAll( "\\s", "" ).split( "/" );

		if( tags.length == 0 )
		{
			return new BerTLV();
		}

		BerTLV res = find( (int)Bin( tags[0] ).asU32(), 1 );

		for( int i = 1; i < tags.length; ++i )
		{
			res = res.find( (int)Bin( tags[i] ).asU32(), 1 );
		}
		return res;
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Представить список BER-TLV в виде многострочного текста для вывода на печать.
	 * @param offset - Сколько пробелов добавлять слева.
	 * @param dictionary - Словарь тегов. Может быть null.
	 */
	public String toString( int offset ) // TODO: BerTLVList: support TagDictionary
	{
		char[] offset_arr = new char[offset];
		Arrays.fill( offset_arr, ' ' );

		StringBuilder res = new StringBuilder( 300 );
		for( int i = 0; i < recs.size(); ++i )
		{
			final BerTLV rec = recs.get( i );
			res.append( offset_arr );
			String tag = Integer.toHexString( rec.tag ).toUpperCase();
			res.append( tag.length() % 2 == 0 ? tag : "0" + tag );

			if( !rec.isConstructed() && (rec.value.size() > 8) )
			{
				res.append( " [" + rec.value.size() + "]" );
			}

//			if( dictionary != null )
//			{
//				String desc = dictionary.getDescription( rec.tag );
//				if( !desc.isEmpty() )
//				{
//					res.append( " -- " + desc );
//				}
//			}

			res.append( ":\n" );

			if( rec.isConstructed() )
			{
				res.append( new BerTLVList( rec.value ).toString( offset + 4 ) ); // , dictionary ) );
				continue;
			}

			StringBuilder str = new StringBuilder( 200 );
			str.append( offset_arr );
			str.append( "    " );
			str.append( rec.value.Hex( 1, 8, 16, 0 ) );

			for( int k = 0; k < str.length(); ++k )
			{
				if( str.charAt( k ) == '\n' )
				{
					++k;
					str.insert( k, offset_arr );
					str.insert( k, "    " );
				}
			}
			res.append( str );
			res.append( '\n' );
		}
		return res.toString();
	}

	// ---------------------------------------------------------------------------------------------------------------------
	@Override
	public String toString()
	{
		return toString( 0 );
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * @return Cписок BER-TLV записей в виде байтового массива.
	 */
	public Binary toBin()
	{
		Binary bin = new Binary();

		for( int i = 0; i < recs.size(); ++i )
		{
			bin.add( recs.get( i ).toBin() );
		}
		return bin;
	}

}
