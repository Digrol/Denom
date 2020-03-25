// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.net.http;

import javax.net.ssl.SSLSocketFactory;

import org.denom.Ex;
import org.denom.format.JSONObject;
import org.denom.log.ILog;

/**
 * Клиент для взаимодействия с HTTP-REST-JSON сервисами
 */
public class RestClient
{
	private final String baseUrl;
	private final HttpClient httpClient;

	// -----------------------------------------------------------------------------------------------------------------
	public RestClient( String baseUrl )
	{
		this( baseUrl, null );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public RestClient( String baseUrl, SSLSocketFactory sslSocketFactory )
	{
		this.baseUrl = baseUrl;
		this.httpClient = new HttpClient().setSslSocketFactory( sslSocketFactory );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public RestClient setLog( ILog log )
	{
		this.httpClient.setLog( log );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param readTimeoutMs - таймаут ожидания ответа. 0 = ожидать бесконечность
	 */
	public RestClient setReadTimeoutMs( int readTimeoutMs )
	{
		this.httpClient.setReadTimeoutMs( readTimeoutMs );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Отправить HTTP-POST запрос и считать ответ в виде JSON.<br>
	 * В запросе будут HTTP-заголовки 'Content-Length' и 'Content-Type: application/json; charset=utf-8'.<br>
	 * В случае ошибочного HTTP-статуса в ответе будет брошена ошибка.<br>
	 * @param requestPath - путь запроса относительно базового URL (URL = baseUrl + / + path )
	 * @param requestData - JSON-тело запроса
	 * @return JSON-ответ
	 */
	public JSONObject post( String requestPath, JSONObject requestData )
	{
		HttpRequest request = new HttpRequest( baseUrl + '/' + requestPath, "POST" );
		request.setBody( requestData );

		request.addHeader( "Content-Type", "application/json; charset=utf-8" );
		request.addHeader( "Content-Length", String.valueOf( request.body.length ) );

		HttpResponse response = httpClient.transmit( request );
		response.checkStatus();

		JSONObject respJSON = response.asJSON();
		return respJSON;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Отправить HTTP-GET запрос и считать ответ в виде JSON.<br>
	 * В запросе будет HTTP-заголовок 'Content-Type: application/x-www-form-urlencoded; charset=utf-8'.<br>
	 * В случае ошибочного HTTP-статуса в ответе будет брошена ошибка.<br>
	 * @param requestPath - путь запроса относительно базового URL (URL = baseUrl + / + path )
	 * @param queryParams - список параметров [key, value] для формирования строки запроса (url?key1=val1&key2=val2)
	 * @return JSON-ответ
	 */
	public JSONObject get( String requestPath, String[]... queryParams )
	{
		String queryURL = HttpRequest.formQueryUrl( baseUrl + '/' + requestPath, queryParams );
		HttpRequest request = new HttpRequest( queryURL, "GET" );
		request.addHeader( "Content-Type", "application/x-www-form-urlencoded; charset=utf-8" );

		HttpResponse response = httpClient.transmit( request );
		response.checkStatus();

		JSONObject respJSON = response.asJSON();
		return respJSON;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Отправить запрос {@link #post(String, JSONObject)} и считать ответ.
	 * Если JSON-ответ содержит поле "Error Code" != 0, будет брошена ошибка с текстом из поля "Error Message".
	 */
	public JSONObject call( String path, JSONObject requestData )
	{
		JSONObject response = post( path, requestData );

		int errorCode = response.optInt( "Error Code", 0 );
		if( errorCode != 0 )
		{
			 Ex.THROW( errorCode, response.optString( "Error Message", "No description" ) );
		}

		return response;
	}

}
