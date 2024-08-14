// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.scp81.http;

import java.util.StringTokenizer;
import java.util.function.Consumer;

import org.denom.*;
import org.denom.log.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.*;

/**
 * Парсит входящий байтовый поток как HTTP-запросы.
 */
public class HttpReqParser
{
	private static final int STATE_STATUS_LINE  = 1;
	private static final int STATE_HEADER_LINE  = 2;
	private static final int STATE_BODY_BINARY  = 3;
	private static final int STATE_CHUNKED_LEN  = 4;
	private static final int STATE_CHUNKED_DATA = 5;

	private int parseState = 0;
	private Binary recievedData = Bin();
	private int parseOffset = 0;
	private HttpReq curReq;
	private int contentLen = 0;
	private boolean isChunked = false;
	private int chunkLen = 0;

	private Consumer<HttpReq> funcOnHttpReq;

	Binary inBuf = Bin().reserve( 256 );

	ILog log = null;

	// -----------------------------------------------------------------------------------------------------------------
	public HttpReqParser()
	{
		init();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Если лог задан, то будет печатать в него полученный HTTP-запрос.
	 */
	public HttpReqParser setLog( ILog log )
	{
		this.log = log;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public HttpReqParser setOnHttpReq( Consumer<HttpReq> funcOnHttpReq )
	{
		this.funcOnHttpReq = funcOnHttpReq;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void init()
	{
		parseState = STATE_STATUS_LINE;
		parseOffset = 0;
		curReq = new HttpReq();
		contentLen = 0;
		isChunked = false;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void append( final Binary data )
	{
		int offset = 0;
		while( offset < data.size() )
		{
			int partSize = Math.min( 256, data.size() - offset );
			recievedData.add( data, offset, partSize );
			offset += partSize;

			while( processRecievedData() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void gotFullRequest()
	{
		curReq.host = curReq.headers.get("Host");

		recievedData.assign( recievedData, parseOffset, recievedData.size() - parseOffset );
		HttpReq req = curReq;
		init();

		if( log != null )
		{
			log.writeln( Colors.DARK_GRAY, "HTTP Request:" );
			log.writeln( HttpReq.COLOR, req.toString() );
		}
		MUST( funcOnHttpReq != null, "Response handler not set" );
		funcOnHttpReq.accept( req );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return false - если в буфере мало данных и нужны ещё данные для их обработки.
	 * true - часть данных обработано, можно вызвать метод повторно.
	 */
	private boolean processRecievedData()
	{
		switch( parseState )
		{
			case STATE_STATUS_LINE:
			{
				String curStr = getLine();
				if( curStr == null )
					return false;

				// method SP request-target SP HTTP-version
				StringTokenizer st = new StringTokenizer( curStr );
				MUST( st.hasMoreTokens(), "Wrong HTTPRequest: StatusLine" );
				curReq.method = st.nextToken();
				MUST( st.hasMoreTokens(), "Wrong HTTPRequest: StatusLine" );
				curReq.requestTarget = st.nextToken();
				MUST( st.hasMoreTokens(), "Wrong HTTPRequest: StatusLine" );
				String httpVersion = st.nextToken();
				MUST( httpVersion.equals( "HTTP/1.1" ) && !st.hasMoreTokens(), "Wrong HTTPRequest: StatusLine" );
				parseState = STATE_HEADER_LINE;
				return true;
			}

			case STATE_HEADER_LINE:
			{
				String curStr = getLine();
				if( curStr == null )
					return false;
			
				if( !curStr.isEmpty() )
				{	// Строка с заголовком
					int index = curStr.indexOf( ':' );
					MUST( index > 0, "Wrong HTTPRequest: HeaderLine" );
					String key = curStr.substring( 0, index );
					String value = curStr.substring( index + 1 ).trim();
					if( key.equals( "Content-Length" ) )
					{
						contentLen = Integer.valueOf( value );
						curReq.headers.put( key, value );
					}
					else if( key.equals( "Transfer-Encoding" ) )
					{
						MUST( value.equals( "chunked" ), "Wrong HTTPRequest: HeaderLine" );
						isChunked = true;
					}
					else
					{
						curReq.headers.put( key, value );
					}
					return true;
				}

				// Пустая строка -> Конец заголовков, ждём тело, если должно быть
				if( contentLen != 0 )
				{
					MUST( !isChunked, "Wrong HTTPRequest: chunked or content-length" );
					parseState = STATE_BODY_BINARY;
					return true;
				}

				if( isChunked )
				{
					parseState = STATE_CHUNKED_LEN;
					return true;
				}

				// нет тела
				gotFullRequest();
				return true;
			}

			case STATE_BODY_BINARY:
			{
				int restLen = (recievedData.size() - parseOffset);
				// Ждём тело целиком
				if( restLen < contentLen )
					return false;

				MUST( restLen == contentLen, "Wrong HTTPRequest: more data than Content-Length" );
				curReq.body = recievedData.slice( parseOffset, contentLen );

				gotFullRequest();
				return true;
			}

			// Структура Chunked-Body без 'chunk-extension' и 'trailer', https://www.rfc-editor.org/rfc/rfc7230#section-4.1
			// Chunked-Body =
			//     *chunk
			//     last-chunk
			//     CRLF
			// chunk =
			//     chunk-size CRLF
			//     chunk-data CRLF
			// chunk-size =
			//     1*HEX
			// last-chunk =
			//     1*("0") CRLF

			case STATE_CHUNKED_LEN:
			{
				String curStr = getLine();
				if( curStr == null )
					return false;

				chunkLen = Integer.valueOf( curStr, 16 );
				parseState = STATE_CHUNKED_DATA;

				return true;
			}

			case STATE_CHUNKED_DATA:
			{
				// Ждём, когда будут приняты все данные чанка и CRLF
				if( (recievedData.size() - parseOffset) < (chunkLen + 2) )
					return false;

				Binary chunkData = recievedData.slice( parseOffset, chunkLen );
				curReq.body.add( chunkData );
				parseOffset += chunkLen;

				MUST( (recievedData.get( parseOffset ) == '\r') && (recievedData.get( parseOffset + 1 ) == '\n'), "Wrong HTTPRequest: chunked CRLF" );
				parseOffset += 2;

				if( chunkLen == 0 ) // Last chunk
				{
					gotFullRequest();
				}
				else
				{
					parseState = STATE_CHUNKED_LEN;
				}
				return true;
			}

			default:
				THROW( "Wrong parse state" );
		}

		return false;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает следующую строку из принятых, но не обработанных данных.
	 * @return null, если символы конца строки ещё не получены.
	 */
	private static final Binary crlf = Bin("0d0a");
	private String getLine()
	{
		int offsetCRLF = recievedData.indexOf( crlf, parseOffset );
		if( offsetCRLF == -1 )
			return null;

		String s = new String( recievedData.getDataRef(), parseOffset, offsetCRLF - parseOffset, Strings.UTF8 );
		parseOffset = offsetCRLF + 2;
		return s;
	}
}
