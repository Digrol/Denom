// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv;

import org.denom.Binary;
import org.denom.format.BerTLV;

/**
 * Information about one BerTLV data object.
 */
public class TagInfo
{
	/**
	 * Examples: 0x9F37;  TagEmv.TransactionSequenceCounter
	 */
	public int tag;

	/**
	 * Examples: "Signed Dynamic Application Data",  Transaction Currency Code
	 */
	public String name;

	/**
	 * Can this object set the Card?
	 */
	public boolean fromCard;

	/**
	 * The length (in bytes) of the Value field of this TLV object must not be less than 'minLen'.
	 */
	public int minLen;

	/**
	 * The length (in bytes) of the Value field of this TLV object must not be greater than 'maxLen'.
	 */
	public int maxLen;

	/**
	 * see TagInfo.Format
	 */
	public Format format;

	/**
	 * Some textual description of data object.
	 */
	public String description;

	/**
	 * Template Tag in which this TLV is to occur.
	 */
	public int template;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Identification of Value format
	 */
	public static enum Format
	{
		B,
		// BCD encoded, right justified with leading 0x00
		N,
		// BCD encoded, left justified, and padded with trailing 'F's
		CN,
		// ASCII encoded, left justified, and padded with trailing 0x00
		AN,
		// ASCII encoded, left justified, and padded with trailing 0x00
		ANS
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TagInfo( int tag, String name, Format format, int minLen, int maxLen, boolean fromCard, int template, String description )
	{
		this.tag = tag;
		this.name = name;
		this.format = format;
		this.minLen = minLen;
		this.maxLen = maxLen;
		this.fromCard = fromCard;
		this.template = template;
		this.description = description;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Tests (this.minLen <= valueLen <= this.maxLen)?
	 */
	public boolean isGoodLen( int valueLen )
	{
		return (valueLen >= minLen) && (valueLen <= maxLen);
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean isGoodLen( Binary valueField )
	{
		int len = valueField.size();
		return (len >= minLen) && (len <= maxLen);
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean isGoodLen( BerTLV tlv )
	{
		int len = tlv.value.size();
		return (len >= minLen) && (len <= maxLen);
	}
}
