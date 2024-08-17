// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.scp81.http;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.denom.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.*;

/**
 * HTTP-запрос.
 */
public class HttpReq
{
	public static final int COLOR = 0xFFFFC020;

	/**
	 * Метод запроса: GET, POST и т.д.
	 */
	public String method;

	/**
	 * Имя хоста. Например:  'example.org', 'localhost:80'
	 */
	public String host;

	/**
	 * Адрес ресурса на сервере, например: '/index.html', '/work/doit/job1'
	 */
	public String requestTarget;

	/**
	 * Заголовки запроса.
	 */
	public final HashMap< String, String > headers = new HashMap<>();

	/**
	 * Тело запроса.
	 */
	public Binary body = Bin();

	public HttpReq() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Имя хоста добавляется в список заголовков.
	 */
	public HttpReq( String host, String requestTarget, String method )
	{
		this.host = host;
		this.requestTarget = requestTarget;
		this.method = method;
		addHeader( "Host", host );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить заголовок запроса.
	 * @param key - название (напр. 'Content-Type')
	 * @param value - значение (напр. 'application/json; charset=utf-8')
	 */
	public HttpReq addHeader( String key, String value )
	{
		headers.put( key, value );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить заголовок запроса.
	 * @param header - заголовок (напр. 'Content-Type: text/html; charset=utf-8')
	 */
	public HttpReq addHeaderLine( String header )
	{
		int splitIndex = header.indexOf( ':' );
		MUST( splitIndex != -1, "Wrong header" );
		headers.put( header.substring( 0, splitIndex ), header.substring( splitIndex + 1 ).trim() );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать тело запроса.
	 * Запоминается ссылка на переданный массив. Копию, если нужно, сделать снаружи метода.
	 */
	public HttpReq setBody( Binary bodyBin )
	{
		body = bodyBin;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public String getStartLine()
	{
		StringBuilder sb = new StringBuilder();
		sb.append( method );
		sb.append( ' ' );
		sb.append( requestTarget );
		sb.append( ' ' );
		sb.append( "HTTP/1.1\r\n" );
		return sb.toString();
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
		String startLine = getStartLine();
		String headersStr = getHeadersStr();
		String s = startLine + headersStr + "\r\n";

		Binary b = Bin().fromUTF8(s );
		if( (body != null) && !body.empty() )
			b.add( body );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public String toString()
	{
		String s = getStartLine() + getHeadersStr() + "\r\n";
		if( (body != null) && !body.empty() )
		{
			s += String.format( Locale.US, "Body [%d]: \r\n", body.size() );
			s += body.Hex( 1, 8, 32, 0 );
		}
		return s;
	}
}
