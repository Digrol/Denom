// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.net.http;

import java.util.*;
import java.nio.charset.Charset;

import org.denom.format.JSONObject;

import static org.denom.Ex.*;

/**
 * HTTP-ответ.
 */
public class HttpResponse
{
	/**
	 * Код ответа
	 */
	public final int code;

	/**
	 * Текст ответа
	 */
	public final String message;

	/**
	 * Заголовки ответа
	 */
	public final Map<String, List<String>> headers;

	/**
	 * Тело ответа (или ошибки)
	 */
	public final byte[] body;

	// -----------------------------------------------------------------------------------------------------------------
	public HttpResponse( int responseCode, String responseMessage, Map<String, List<String>> headers, byte[] body )
	{
		this.code = responseCode;
		this.message = responseMessage;
		this.headers = headers;
		this.body = body;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверить статус ответа, бросить ошибку если статус ошибочный
	 */
	public HttpResponse checkStatus()
	{
		MUST( code >= 100, "Wrong status code: " + code );

		// если код ошибки
		if( code >= 400 )
		{
			StringBuilder sb = new StringBuilder();
			sb.append( "HTTP Error " );
			sb.append( code );
			sb.append( ' ' );
			if( message != null )
			{
				sb.append( message );
			}

			sb.append( '\n' );
			if( body != null )
			{
				sb.append( asString() );
			}
			
			THROW( code, sb.toString() );
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить кодировку ответа из первого заголовка 'Content-Type' с указанием 'charset='
	 * @return Кодировка или null если не найдена
	 */
	public Charset getCharset()
	{
		List<String> contentTypeVals = headers.get( "Content-Type" );
		if( contentTypeVals == null )
		{
			return null;
		}

		for( String contentTypeVal : contentTypeVals )
		{
			int charsetStart = contentTypeVal.indexOf( "charset=" );
			if( charsetStart != -1 )
			{
				String charsetName = contentTypeVal.substring( charsetStart + 8 ).trim();
				return Charset.forName( charsetName );
			}
		}

		return null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Тело ответа в виде строки в кодировке ответа или UTF-8 если кодировка явно не указана
	 */
	public String asString()
	{
		Charset respCharset = getCharset();
		if( respCharset == null )
		{
			respCharset = Charset.forName( "UTF-8" );
		}
		return asString( respCharset );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Тело ответа в виде строки в указанной кодировке.
	 */
	public String asString( Charset charset )
	{
		return new String( body, charset );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Тело ответа в виде JSON.
	 */
	public JSONObject asJSON()
	{
		return new JSONObject( asString() );
	}

}
