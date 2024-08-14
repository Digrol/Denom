// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.net.http;

import java.util.*;

import java.io.UnsupportedEncodingException;
import java.net.*;
import java.nio.charset.Charset;

import org.denom.*;
import org.denom.format.JSONObject;

import static org.denom.Ex.*;

/**
 * HTTP-запрос.
 */
public class HttpRequest
{
	/**
	 * URL запроса
	 */
	public final String url;

	/**
	 * Метод запроса
	 */
	public final String method;

	/**
	 * Заголовки запроса
	 */
	public final List<Pair<String, String>> headers;

	/**
	 * Тело запроса
	 */
	public byte[] body;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param url - URL (напр. 'http://myhost.org')
	 * @param method - метод запроса (напр. POST, GET и т.п.)
	 */
	public HttpRequest( String url, String method )
	{
		this.url = url;
		this.method = method;
		headers = new ArrayList<>();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить заголовок запроса
	 * @param key - название (напр. 'Content-Type')
	 * @param value - значение (напр. 'application/json; charset=utf-8')
	 */
	public HttpRequest addHeader( String key, String value )
	{
		headers.add( Pair.of( key, value ) );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить заголовок запроса
	 * @param header - заголовок (напр. 'Content-Type: text/html; charset=utf-8')
	 */
	public HttpRequest addHeader( String header )
	{
		int splitIndex = header.indexOf( ':' );
		MUST( splitIndex != -1, "Wrong header" );
		headers.add( Pair.of( header.substring( 0, splitIndex ), header.substring( splitIndex + 1 ).trim() ) );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать тело запроса в виде байтового массива.
	 */
	public HttpRequest setBody( byte[] requestData )
	{
		body = requestData;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать тело запроса. Строка будет преобразована в байты с кодировкой UTF-8.
	 */
	public HttpRequest setBody( String requestStr )
	{
		return setBody( requestStr, Strings.UTF8 );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать тело запроса. Строка будет преобразована в байтовый массив с указанной кодировкой.
	 */
	public HttpRequest setBody( String requestStr, Charset charset )
	{
		return setBody( requestStr.getBytes( charset ) );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать тело запроса в виде JSON-объекта. JSON будет преобразован в байтовый массив с кодировкой UTF-8.
	 */
	public HttpRequest setBody( JSONObject requestJson )
	{
		return setBody( requestJson.toString() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сформировать URL-запрос с параметрами вида - url?param1=val1&param2=val2 и т.п.)
	 * @param url - URL
	 * @param queryParams - список параметров [key, value] для формирования строки запроса
	 */
	public static String formQueryUrl( String url, String[]... queryParams )
	{
		try
		{
			StringBuilder sb = new StringBuilder();
			sb.append( url );

			for( int i = 0; i < queryParams.length; ++i )
			{
				String[] param = queryParams[ i ];
				MUST( param.length == 2, "Wrong url params" );

				sb.append( (i == 0) ? '?' : '&' );
				sb.append( URLEncoder.encode( param[ 0 ], "utf-8" ) );
				sb.append( '=' );
				sb.append( URLEncoder.encode( param[ 1 ], "utf-8" ) );
			}

			return sb.toString();
		}
		catch( UnsupportedEncodingException ex )
		{
			THROW( ex );
			return null;
		}

	}

}
