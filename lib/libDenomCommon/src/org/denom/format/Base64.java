// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.format;

import org.denom.Binary;

import static org.denom.Ex.*;

/**
 * Кодирование массива байтов в виде Base64-строки.<br>
 * см. RFC 2045 - https://www.ietf.org/rfc/rfc2045.txt, раздел 6.8.
 */
public class Base64
{
	/**
	 * PADDING_BYTE: '='
	 * Доп. символы: '+' и '/'
	 */
	public final static int MODE_CLASSIC = 1;
	
	/**
	 * PADDING_BYTE: '.'
	 * Доп. символы: '-' и '_'
	 */
	public final static int MODE_URL = 2;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Классический режим.
	 */
	public Base64()
	{
		this( MODE_CLASSIC );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * см. константы MODE_*
	 */
	public Base64( int mode )
	{
		switch( mode )
		{
			case MODE_CLASSIC:
				encodeTable = ENCODE_TABLE_CLASSIC;
				paddingByte = '=';
				break;

			case MODE_URL:
				encodeTable = ENCODE_TABLE_URL;
				paddingByte = '.';
				break;

			default:
				paddingByte = 0;
				encodeTable = null;
				decodeTable = null;
				THROW( "Unsupported mode for Base64: " + mode );
		}
	}

	private final byte paddingByte;
	private final char[] encodeTable;
	private int[] decodeTable = null; // Инициализируется при вызове decode()

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Закодировать байтовый массив в виде строки Base64.
	 * @param arr - Массив байтов.
	 */
	public String encode( final byte[] arr )
	{
		int len = arr.length;
		if( len == 0 )
		{
			return "";
		}

		StringBuilder encodedStr = new StringBuilder( len * 4 / 3 );

		int i = 0;
		for( ; (i + 2) < len; i += 3 )
		{
			int num = (( arr[ i ] & 0xFF) << 16) | ((arr[ i + 1 ] & 0xFF) << 8) | (arr[ i + 2 ] & 0xFF);
			encodedStr.append( encodeTable[ num >> 18 ] );
			encodedStr.append( encodeTable[ (num >> 12) & 0x3F ] );
			encodedStr.append( encodeTable[ (num >> 6) & 0x3F ] );
			encodedStr.append( encodeTable[ num & 0x3F ] );
		}
		if( (len - i) == 1 )
		{
			int b = arr[ i ] & 0xFF;
			encodedStr.append( encodeTable[ b >> 2 ] );
			encodedStr.append( encodeTable[ (b << 4) & 0x3F ] );
			encodedStr.append( (char)paddingByte );
			encodedStr.append( (char)paddingByte );
		}
		if( (len - i) == 2 )
		{
			int b = ((arr[ i ] & 0xFF) << 8) | (arr[ i + 1 ] & 0xFF);
			encodedStr.append( encodeTable[ b >> 10 ] );
			encodedStr.append( encodeTable[ (b >> 4) & 0x3F ] );
			encodedStr.append( encodeTable[ (b << 2) & 0x3F ] );
			encodedStr.append( (char)paddingByte );
		}

		return encodedStr.toString();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Закодировать байтовый массив в виде строки Base64.
	 * @param bin - Массив байтов.
	 */
	public String encode( final Binary bin )
	{
		return encode( bin.getBytes() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Из Base64-строки получить массив байтов.
	 * @param encodedStr - Строка в Base64, может содержать пробелы, переводы строк, табуляции.
	 */
	public Binary decode( final String encodedStr )
	{
		Binary bin = new Binary();
		decode( encodedStr, bin );
		return bin;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void initDecodeTable()
	{
		if( decodeTable != null )
			return;
		
		decodeTable = new int[ 256 ];

		for( int i = 0; i < encodeTable.length; ++i )
		{
			decodeTable[ encodeTable[ i ] ] = i;
		}
		decodeTable[ paddingByte ] = 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Из Base64-строки получить массив байтов.
	 * @param encodedStr - Строка в Base64, может содержать пробелы, переводы строк, табуляции.
	 * @param bin - Массив байтов, заполняется результатом.
	 */
	public void decode( final String encodedStr, Binary bin )
	{
		initDecodeTable();

		bin.clear();
		String encStr = encodedStr.replaceAll( "\\s", "" );
		bin.reserve( encStr.length() );

		MUST( (encStr.length() & 0x03) == 0, "Длина строки Base64 не кратна 4" );

		for( int i = 0; i < encStr.length(); i += 4 )
		{
			int b1 = decodeTable[ encStr.charAt( i ) ];
			int b2 = decodeTable[ encStr.charAt( i + 1 ) ];
			int b3 = decodeTable[ encStr.charAt( i + 2 ) ];
			int b4 = decodeTable[ encStr.charAt( i + 3 ) ];

			MUST( (b1 | b2 | b3 | b4) < 0x40, "Некорректные символы в строке Base64" );

			bin.add( (b1 << 2) | (b2 >> 4) );

			if( encStr.charAt( i + 2 ) != (char)paddingByte )
			{
				bin.add( (b2 << 4) | (b3 >> 2) );
			}
			if( encStr.charAt( i + 3 ) != (char)paddingByte )
			{
				bin.add( (b3 << 6) | b4 );
			}
		}
	}

	// =================================================================================================================
	private static final char[] ENCODE_TABLE_CLASSIC = new char[]
	{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', //   0 -   9
		'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', //  10 -  19
		'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', //  20 -  29
		'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', //  30 -  39
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', //  40 -  49
		'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', //  50 -  59
		'8', '9', '+', '/'                                //  60 -  63
	};

	private static final char[] ENCODE_TABLE_URL = new char[]
	{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', //   0 -   9
		'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', //  10 -  19
		'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', //  20 -  29
		'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', //  30 -  39
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', //  40 -  49
		'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', //  50 -  59
		'8', '9', '-', '_'                                //  60 -  63
	};

}