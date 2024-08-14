// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.scp81.http;

import java.util.*;

import org.denom.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * HTTP-Response.
 */
public class HttpResp
{
	public static final int COLOR = 0xFF20FFC0;

	public String statusLine;

	public HashMap<String, String> headers = new HashMap<>();
	public Binary body = new Binary();

	// -----------------------------------------------------------------------------------------------------------------
	public HttpResp() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать Status-Line корректно, указав статус и reason.
	 * @param status
	 * @param reasonPhrase may by null
	 * @return this
	 */
	public HttpResp setStatusLine( int status, String reasonPhrase )
	{
		StringBuilder sb = new StringBuilder();
		sb.append( "HTTP/1.1 " );
		sb.append( String.valueOf( status ) );
		sb.append( ' ' );
		if( reasonPhrase != null )
			sb.append( reasonPhrase );

		statusLine = sb.toString();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать Status-Line строкой, возможно некорректной.
	 */
	public HttpResp setStatusLine( String statusLine )
	{
		MUST( statusLine != null, "statusLine == null" );
		this.statusLine = statusLine;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить строку статуса, извлечь код статуса.
	 * @return status
	 */
	public int parseStatus()
	{
		String s = statusLine;
		// HTTP-version SP status-code SP [ reason-phrase ]
		MUST( s.startsWith( "HTTP/1.1 " ), "Wrong HttpResp: StatusLine" );
		s = s.substring( 9 );

		int index = s.indexOf( ' ' );
		MUST( index > 0, "Wrong HttpResp: StatusLine" );
		return Integer.valueOf( s.substring( 0, index ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Распарсить строку статуса, извлечь Reason.
	 * @return Reason
	 */
	public String parseReason()
	{
		String s = statusLine;
		// HTTP-version SP status-code SP [ reason-phrase ]
		MUST( s.startsWith( "HTTP/1.1 " ), "Wrong HttpResp: StatusLine" );
		s = s.substring( 9 );

		int index = s.indexOf( ' ' );
		MUST( index > 0, "Wrong HttpResp: StatusLine" );
		return s.substring( index + 1, s.length() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить заголовок.
	 * @param key - название (напр. 'Content-Type')
	 * @param value - значение (напр. 'application/json; charset=utf-8')
	 */
	public HttpResp addHeader( String key, String value )
	{
		headers.put( key, value );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать тело запроса.
	 * ВНИМАНИЕ!!! Запоминается ссылка на переданный массив. Копию, если нужно, сделать снаружи метода.
	 */
	public HttpResp setBody( Binary bodyBin )
	{
		body = bodyBin;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public String getHeadersStr()
	{
		StringBuilder sb = new StringBuilder();

		for( Map.Entry<String, String> pair : headers.entrySet() )
		{
			sb.append( pair.getKey() );
			sb.append( ": " );
			sb.append( pair.getValue() );
			sb.append( "\r\n" );
		}

		return sb.toString();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary toBin()
	{
		MUST( statusLine != null, "HttpResp: statusLine == null" );
		StringBuilder sb = new StringBuilder();
		sb.append( statusLine );
		sb.append( "\r\n" );
		sb.append( getHeadersStr() );
		sb.append( "\r\n" );

		Binary b = Bin().fromUTF8( sb.toString() );
		if( (body != null) && !body.empty() )
			b.add( body );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append( statusLine );
		sb.append( "\r\n" );
		sb.append( getHeadersStr() );
		sb.append( "\r\n" );
		if( (body != null) && !body.empty() )
		{
			sb.append( String.format( "Body [%d]: \r\n", body.size() ) );
			sb.append( body.Hex( 1, 8, 32, 0 ) );
		}
		return sb.toString();
	}
}
