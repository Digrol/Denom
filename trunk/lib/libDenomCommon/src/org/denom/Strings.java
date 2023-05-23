// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom;

import java.util.*;
import java.nio.charset.*;
import java.text.SimpleDateFormat;

public class Strings
{
	/**
	 * Символ конца строки
	 */
	public static String ln = "\n";

	static
	{
		try
		{
			ln = System.getProperty("line.separator");
		}
		catch( Throwable ex ) {}
	}

	public static final Charset CP1251 = Charset.forName( "CP1251" );
	public static final Charset UTF8   = Charset.forName( "UTF-8" );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверить, является ли строка str строкой в формате HEX.
	 * Строка должна содержать чётное число (больше 0) шестнадцатиричных символов.
	 */
	public static boolean isHex( String str )
	{
		long count = 0;
		for( char ch : str.toCharArray() )
		{
			if( (ch == ' ') || (ch == '\t') || (ch == '\n') || (ch == '\r') )
				continue;

			if( (ch >= '0') && (ch <= '9') || (ch >= 'A') && (ch <= 'F') || (ch >= 'a') && (ch <= 'f') )
			{
				++count;
			}
			else
			{
				return false;
			}
		}
		return ((count & 1) == 0) && (count > 0); // Должно быть чётное число цифр и > 0
	}
	 
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверить, является ли строка str строкой в формате HEX.
	 * Строка должна содержать чётное число (больше 0) шестнадцатиричных символов.
	 * Плюс проверяется, что количество байт, закодированных в строке совпадает с требуемым.
	 * @param wantLen - Длина Binary, полученного из строки.
	 * @return true - если строка удовлетворяет условиям
	 */
	public static boolean isHex( String str, int wantLen )
	{
		boolean res = isHex( str );
		if( !res )
		{
			return false;
		}
		return new Binary( str ).size() == wantLen;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Дополнить строку слева до требуемой длины указанными символами.
	 * @param str - Строка, которую нужно дополнить.
	 * @param reqLen - Требуемая длина.
	 * @param symbol - Символ-заполнитель.
	 */
	public static String PadLeft( String str, int reqLen, char symbol )
	{
		Ex.MUST( str.length() <= reqLen, "Длина строки больше требуемого размера" );

		if( str.length() == reqLen )
		{
			return str;
		}

		char[] padded = new char[ reqLen ];
		int padLen = reqLen - str.length();
		Arrays.fill( padded, 0, padLen, symbol );
		str.getChars( 0, str.length(), padded, padLen );
		return new String( padded );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Дополнить строку справа до требуемой длины указанными символами.
	 * @param str - Строка, которую нужно дополнить.
	 * @param reqLen - Требуемая длина.
	 * @param symbol - Символ-заполнитель.
	 */
	public static String PadRight( String str, int reqLen, char symbol )
	{
		Ex.MUST( str.length() <= reqLen, "Длина строки больше требуемого размера" );

		if( str.length() == reqLen )
		{
			return str;
		}

		char[] padded = new char[ reqLen ];
		str.getChars( 0, str.length(), padded, 0 );
		Arrays.fill( padded, str.length(), padded.length, symbol );

		return new String( padded );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Возвращает строку с текущим временем в формате: yyyy-MM-dd HH:mm:ss.SSS
	 */
	public static String currentDateTime()
	{
		return new SimpleDateFormat( "yyyy-MM-dd HH:mm:ss.SSS" ).format( new Date() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param format - формат даты и времени, например yyyy-MM-dd HH:mm:ss.SSS
	 * См. class java.text.SimpleDateFormat
	 * @return Возвращает строку с текущим временем в заданном формате.
	 */
	public static String currentDateTime( String format )
	{
		return new SimpleDateFormat( format ).format( new Date() );
	}
	
}
