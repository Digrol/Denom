// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.format;

import java.io.*;
import java.util.*;

import org.denom.*;

import static org.denom.Ex.*;
import static org.denom.Binary.*;

/**
 * Словарь описаний тегов - загружает и хранит описания тегов.
 */
public class TagDictionary
{
	private static final String TAG_PREFIX = "TagDesc ";
	private static final String KEY_AID_LIST = "AID List";

	private final Map<Long, String> descriptions = new HashMap<>();
	private final List<Binary> aids = new ArrayList<>();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Cоздать пустой словарь описаний тегов.
	 */
	public TagDictionary() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Загрузить словарь описаний тегов из файла.
	 */
	public void load( String fileName )
	{
		MUST( !fileName.isEmpty(), "The path can't be empty" );
		load( new JSONObject().loadWithComments( fileName ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void load( InputStream is )
	{
		load( new JSONObject().loadWithComments( is ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Загрузить словарь описаний тегов из json.
	 * @param jo - формат описаний тегов: key - HEX-String, value - String; <br>
	 * формат списка инстансов: key = KEY_AID_LIST, value - список инстансов через запятую
	 */
	public void load( JSONObject jo )
	{
		aids.clear();
		descriptions.clear();

		for( String key : jo.keySet() )
		{
			if( key.startsWith( TAG_PREFIX ) )
			{
				String tag = key.substring( TAG_PREFIX.length() );
				descriptions.put( Bin( tag ).asU32(), jo.getString( key ) );
			}

			if( key.equals( KEY_AID_LIST ) )
			{
				String[] aidList = jo.getString( key ).split( "," );
				for( String aid : aidList )
				{
					if( !aid.isEmpty() )
					{
						aids.add( Bin( aid ) );
					}
				}
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить описание тега.
	 */
	public String getDescription( long tag )
	{
		String val = descriptions.get( tag );
		return val != null ? val : "";
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подходит ли словарь для инстанса с заданным AID. Если инстансы не заданы - подходит для всех AID.
	 */
	public boolean isDictionaryForAID( Binary aid )
	{
		if( aids.isEmpty() )
		{
			return true;
		}
		return aids.contains( aid );
	}

}
