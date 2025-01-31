// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8;

import java.util.HashMap;
import org.denom.smartcard.emv.ITagDictionary;
import org.denom.smartcard.emv.TagInfo;

/**
 * Cловарь со списком тегов и информацией о них.
 * В этом словаре все теги из EMV Сontactless Book C-8, Kernel 8 Specification v1.1, Annex A. Data Dictionary.
 */
public class TagDictKernel8 implements ITagDictionary
{
	/**
	 * key: Tag
	 */
	public static HashMap<Integer, TagInfo> tags;

	/**
	 * key: Tag Name
	 */
	public static HashMap<Integer, TagInfo> tagsByName;

	// -----------------------------------------------------------------------------------------------------------------
	public TagDictKernel8()
	{
		initDict();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private synchronized static void initDict()
	{
		tags = new HashMap<Integer, TagInfo>();
		tagsByName = new HashMap<Integer, TagInfo>();

		// TODO: наполнить словать тегов
		//add( );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void add( int tag, String name, int minLen, int maxLen, boolean fromCard )
	{
		TagInfo info = new TagInfo( tag, name, minLen, maxLen, fromCard );
		tags.put( tag, info );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public TagInfo find( int tag )
	{
		return null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public TagInfo find( String name )
	{
		return null;
	}
}
