// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.net.http;

import java.net.*;
import javax.net.ssl.SSLSocketFactory;

import static org.denom.Ex.*;

/**
 * Клиент для SOAP-сервисов SLS.
 */
public class SOAPClient
{
	private static final String RETURN_TAG = "<return>";
	private static final String RETURN_CTAG = "</return>";
	private static final String FAULT_TAG = "<S:Fault";
	private static final String FAULT_STRING_TAG = "<faultstring>";
	private static final String FAULT_STRING_CTAG = "</faultstring>";

	// для ответов из 1с
	private static final String M_RETURN_TAG_START = "<m:return";
	private static final String M_RETURN_CTAG = "</m:return>";

	private HttpClient httpClient;

	private URL serviceURL;
	private String serviceNamespace;

	//------------------------------------------------------------------------------------------------------------------
	/**
	 * Клиент SOAP-сервиса
	 * @param serviceURL - URL сервиса
	 * @param serviceNamespace - namespace сервиса
	 */
	public SOAPClient( String serviceURL, String serviceNamespace )
	{
		this( serviceURL, serviceNamespace, null );
	}

	//------------------------------------------------------------------------------------------------------------------
	/**
	 * Клиент SOAP-сервиса для HTTPS, использующего не добавленный в систему корневой сертификат
	 */
	public SOAPClient( String serviceURL, String serviceNamespace, SSLSocketFactory sslSocketFactory )
	{
		this.serviceNamespace = serviceNamespace;
		try
		{
			this.serviceURL = new URI( serviceURL ).toURL();
		}
		catch( Throwable ex )
		{
			THROW( ex.toString() );
		}
		this.httpClient = new HttpClient().setSslSocketFactory( sslSocketFactory );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызов метода SOAP-сервиса
	 * @param methodName Имя метода
	 * @param parameters список пар - { "имя параметра", "значение параметра" }
	 */
	public String callMethod( final String methodName, final String[][] parameters )
	{
		return callMethod( methodName, "", parameters );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызов метода SOAP-сервиса
	 * @param methodName - Имя метода
	 * @param soapAction - Заголовок
	 * @param parameters - список пар - { "имя параметра", "значение параметра" }
	 * @return Ответ сервера
	 */
	public String callMethod( final String methodName, final String soapAction, final String[][] parameters )
	{
		HttpRequest httpRequest = new HttpRequest( serviceURL.toString(), "POST" );
		httpRequest.addHeader( "Accept", "text/xml" );
		httpRequest.addHeader( "Content-Type", "text/xml;charset=utf-8" );
		httpRequest.addHeader( "Connection", "keep-alive" );
		httpRequest.addHeader( "SOAPAction", "\"" + soapAction + "\"" );

		httpRequest.setBody( formatSoapRequest( methodName, formParamsString( parameters ) ) );

		HttpResponse httpResponse = httpClient.transmit( httpRequest );
		httpResponse.checkStatus();

		return getReturnValue( httpResponse.asString() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	// Формирование SOAP-запроса
	private String formatSoapRequest( String methodName, String parameters )
	{
		StringBuilder str = new StringBuilder( 200 + parameters.length() );
		
		str.append( "<?xml version=\"1.0\" ?><S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\"><S:Body><ns2:" );
		str.append( methodName );
		str.append( " xmlns:ns2=\"" );
		str.append( serviceNamespace );
		str.append( "\">" );
		str.append( parameters );
		str.append( "</ns2:" );
		str.append( methodName );
		str.append( "></S:Body></S:Envelope>" );

		return str.toString();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private String formParamsString( final String[][] parameters )
	{
		StringBuilder str = new StringBuilder( parameters.length * 50 );
		
		for( String[] entry : parameters )
		{
			MUST( entry.length == 2 );
			str.append( "<" );
			str.append( entry[ 0 ] );
			str.append( ">" );
			str.append( entry[ 1 ] );
			str.append( "</" );
			str.append( entry[ 0 ] );
			str.append( ">" );
		}
		return str.toString();
	}

	// ---------------------------------------------------------------------------------------------------------------------
	// Извлечение данных из SOAP-ответа
	private String getReturnValue( String response )
	{
		int fault_begin = response.indexOf( FAULT_TAG );

		if( fault_begin != -1 )
		{
			int ex_begin = response.indexOf( FAULT_STRING_TAG );
			int ex_end = response.indexOf( FAULT_STRING_CTAG );

			THROW( "Server send error: " + response.substring( ex_begin + FAULT_STRING_TAG.length(), ex_end ) );
		}

		int begin = response.indexOf( RETURN_TAG );
		int end = response.indexOf( RETURN_CTAG );

		if( (begin == -1) || (end == -1) )
		{
			// специфический парсинг для ответов 1С
			int beginM = response.indexOf( M_RETURN_TAG_START );
			int endM = response.indexOf( M_RETURN_CTAG );
			if( (beginM == -1 ) || (endM == -1) )
			{
				return ""; // пустой ответ (для случая если подразумевается void)
			}

			int beginM_End = response.indexOf( '>', beginM + 1);
			return response.substring( beginM_End + 1, endM );
		}

		return response.substring( begin + RETURN_TAG.length(), end );
	}

}
