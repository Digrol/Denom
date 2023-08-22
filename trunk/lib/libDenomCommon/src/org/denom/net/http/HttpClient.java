// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.net.http;

import java.util.List;

import javax.net.ssl.*;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;

import org.denom.*;
import org.denom.log.*;

import static org.denom.Ex.*;

/**
 * Клиент для протокола HTTP.
 * Позволяет сконфигурировать HTTP/HTTPS-соединение;
 * отправить запрос - {@link HttpRequest} и получить на него ответ - {@link HttpResponse}. 
 */
public class HttpClient
{
	private ILog log = new LogDummy();

	private int connectTimeoutMs = 15000;
	private int readTimeoutMs = 15000;
	private SSLSocketFactory sslSocketFactory;

	private int redirectDepth;

	// -----------------------------------------------------------------------------------------------------------------
	public HttpClient() {}

	// -----------------------------------------------------------------------------------------------------------------
	public HttpClient setLog( ILog log )
	{
		if( log != null )
		{
			this.log = log;
		}

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param connectTimeoutMs - таймаут ожидания открытия соединения. 0 = ожидать бесконечность
	 */
	public HttpClient setConnectTimeoutMs( int connectTimeoutMs )
	{
		this.connectTimeoutMs = connectTimeoutMs;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param readTimeoutMs - таймаут ожидания ответа. 0 = ожидать бесконечность
	 */
	public HttpClient setReadTimeoutMs( int readTimeoutMs )
	{
		this.readTimeoutMs = readTimeoutMs;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать SSLSocketFactory для настройки https.
	 * Будет использоваться при работе по HTTPS-протоколу вместо дефолтной реализации
	 * 
	 * @see #trustAllCerts()
	 * @see #trustUserCA(KeyStore)
	 */
	public HttpClient setSslSocketFactory( SSLSocketFactory sslSocketFactory )
	{
		this.sslSocketFactory = sslSocketFactory;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Отправить HTTP-запрос и считать ответ.
	 * @param request - инициализированный запрос
	 */
	public HttpResponse transmit( HttpRequest request )
	{
		return transmit( request.url, request.method, request.headers, request.body );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Отправить HTTP-запрос и считать ответ.
	 * @param url - URL запроса
	 * @param method - метод запроса
	 * @param headers - заголовки запроса или null
	 * @param body - тело запроса или null
	 */
	public HttpResponse transmit( String url, String method, List<Pair<String, String>> headers, byte[] body )
	{
		MUST( (url != null) && !url.isEmpty(), "URL not set!" );
		MUST( (method != null) && !method.isEmpty(), "Method not set!" );

		try
		{
			HttpURLConnection connection = (HttpURLConnection)(new URI( url ).toURL()).openConnection( Proxy.NO_PROXY );

			if( (sslSocketFactory != null ) && (connection instanceof HttpsURLConnection) )
			{
				((HttpsURLConnection)connection).setSSLSocketFactory( sslSocketFactory );
			}

			connection.setConnectTimeout( connectTimeoutMs );
			connection.setReadTimeout( readTimeoutMs );
			connection.setUseCaches( false );
			connection.setAllowUserInteraction( false );

			connection.setRequestMethod( method );
			log.writeln( "HTTP " + connection.getRequestMethod() + " " + connection.getURL() );

			if( headers != null )
			{
				log.writeln( "  request headers:" );
				for( Pair<String, String> header : headers )
				{
					connection.setRequestProperty( header.key, header.value );
					log.writeln( "    " + header.key + ": " + header.value );
				}
			}

			if( (body != null) && (body.length > 0) )
			{
				connection.setDoOutput( true );

				log.writeln( "  request len: " + body.length );
				InputStream requestStream = new ByteArrayInputStream( body ); 
				try( OutputStream connectionStream = connection.getOutputStream() )
				{
					copyStream( requestStream, connectionStream );
				}
			}
			else
			{
				connection.setDoOutput( false );
			}

			int responseCode = connection.getResponseCode();

			// по-умолчанию включены редиректы внутри одного протокола http или https (см. HttpURLConnection.setFollowRedirects)
			// 'ручной' редирект нужен только для редиректа между протоколами http->https, максимальное кол-во редиректов 5
			switch( responseCode )
			{
				case HttpURLConnection.HTTP_MOVED_PERM:
				case HttpURLConnection.HTTP_MOVED_TEMP:
				{
					MUST( redirectDepth < 5, "Too many redirects!" );
					redirectDepth += 1;

					String redirectUrl = connection.getHeaderField( "Location" );
					if( redirectUrl.startsWith( "https" ) )
					{
						log.writeln( "  redirect http -> https" );
					}
					return transmit( redirectUrl, method, headers, body );
				}
			}
			redirectDepth = 0;

			String responseMessage = connection.getResponseMessage();

			log.writeln( "  status: " + responseCode );

			boolean statusOk = (responseCode < 400);

			ByteArrayOutputStream respStream = new ByteArrayOutputStream();
			try( InputStream connectionStream = statusOk ? connection.getInputStream() : connection.getErrorStream() )
			{
				if( connectionStream != null )
				{
					copyStream( connectionStream, respStream );
				}
			}
			byte[] responseData = respStream.toByteArray();
			log.writeln( "  response len: " + responseData.length );

			return new HttpResponse( responseCode, responseMessage, connection.getHeaderFields(), responseData );
		}
		catch( Throwable ex )
		{
			THROW( ex );
			return null;
		}

	}

	// =================================================================================================================
	private final byte[] buf = new byte[ 1024 ];

	private void copyStream( InputStream from, OutputStream to ) throws IOException
	{
		int read;
		while( (read = from.read( buf )) != -1 )
		{
			to.write( buf, 0, read );
		}
		to.flush();
	}

	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * SSLSocketFactory без проверок валидности сертификатов (доверие, срок действия, отозванность и т.п.)
	 * Проверяется только соответствие DNS.
	 */
	public static SSLSocketFactory trustAllCerts()
	{
		try
		{
			SSLContext sc = SSLContext.getInstance( "TLS" );
			sc.init( null, new TrustManager[] { new X509TrustManager()
			{
				@Override
				public X509Certificate[] getAcceptedIssuers()
				{
					return new X509Certificate[ 0 ];
				}
				
				@Override
				public void checkServerTrusted( X509Certificate[] chain, String authType )
				{
					//
				}
				
				@Override
				public void checkClientTrusted( X509Certificate[] chain, String authType )
				{
					//
				}
			} }, new SecureRandom() );
			return sc.getSocketFactory();
		}
		catch( GeneralSecurityException ex )
		{
			THROW( ex );
			return null;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * SSLSocketFactory с пользовательскими CA-сертификатами вместо системных
	 * @param keystore - хранилище CA-сертификатов
	 */
	public static SSLSocketFactory trustUserCA( KeyStore trustStore )
	{
		MUST( trustStore != null, "Trust KeyStore not set!" );

		try
		{
			SSLContext sslContext = SSLContext.getInstance( "TLS" );

			TrustManagerFactory tmf = TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
			tmf.init( trustStore );
			TrustManager[] trustManagers = tmf.getTrustManagers();
			sslContext.init( null, trustManagers, new SecureRandom() );

			return sslContext.getSocketFactory();
		}
		catch( GeneralSecurityException ex )
		{
			THROW( ex );
			return null;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * SSLSocketFactory с пользовательскими CA-сертификатами вместо системных и пользовательскими ключами
	 * (для авторизации по сертификатам)
	 * @param trustStore - хранилище CA-сертификатов
	 * @param keyStore - хранилище ключей
	 * @param keyPassword - пароль от ключей в хранилище
	 */
	public static SSLSocketFactory trustUserCaAndKeys( KeyStore trustStore, KeyStore keyStore, String keyPassword )
	{
		MUST( trustStore != null, "Trust KeyStore not set!" );
		MUST( keyStore != null, "Key KeyStore not set!" );
		MUST( keyPassword != null, "Key Password not set!" );

		try
		{
			SSLContext sslContext = SSLContext.getInstance( "TLS" );

			TrustManagerFactory tmFactory = TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
			tmFactory.init( trustStore );
			TrustManager[] trustManagers = tmFactory.getTrustManagers();

			KeyManagerFactory kmFactory = KeyManagerFactory.getInstance( KeyManagerFactory.getDefaultAlgorithm() );
			kmFactory.init( keyStore, keyPassword.toCharArray() );
			KeyManager[] keyManagers = kmFactory.getKeyManagers();

			sslContext.init( keyManagers, trustManagers, new SecureRandom() );

			return sslContext.getSocketFactory();
		}
		catch( GeneralSecurityException ex )
		{
			THROW( ex );
			return null;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать объект KeyStore, десериализовав его из байтов.
	 * @param keyStoreBin - Содержимое файла-хранилища ключей и сертификатов. На десктопе - jks, Android - bks.
	 * @param keyStoreFormat - формат хранилища, например: "PKCS12", "JKS", "BKS".
	 * @param keyStorePassword - пароль для доступа к хранилищу.
	 */
	public static KeyStore createKeyStore( Binary keyStoreBin, String keyStoreFormat, String keyStorePassword )
	{
		KeyStore keystore = null;
		try
		{
			keystore = KeyStore.getInstance( keyStoreFormat );
			try( InputStream readStream = new ByteArrayInputStream( keyStoreBin.getBytes() ) )
			{
				keystore.load( readStream, keyStorePassword.toCharArray() );
			}
		}
		catch( Exception ex )
		{
			THROW( ex );
		}
		return keystore;
	}

}
