// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.scp81;

import java.util.Map;
import org.denom.Binary;
import org.denom.scp81.TlsConst.*;

import static org.denom.Ex.MUST;

/**
 * Формирование и парсинг Handshake-сообщения Server Hello.
 * RFC 5246, 7.4.1.3.
 */
public class TlsHelloServer
{
	public final int protocol;
	public final Binary random;
	public final Binary sessionID;
	public final int cipherSuite;
	public final int compressionMethod;
	public final Map<Integer, Binary> extensions;

	// -----------------------------------------------------------------------------------------------------------------
	public TlsHelloServer( int version, Binary random, Binary sessionID, int cipherSuite, Map<Integer, Binary> extensions )
	{
		MUST( (random != null) && (sessionID != null) && (extensions != null), "Wrong ClientHello params" );

		this.protocol = version;
		this.random = random;
		this.sessionID = sessionID;
		this.cipherSuite = cipherSuite;
		this.compressionMethod = 0;
		this.extensions = extensions;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TlsHelloServer( Binary message )
	{
		protocol = message.getU16( 0 );
		random = message.slice( 2, 32 );

		int offset = 2 + 32;
		int len = message.get( offset );
		offset++;
		sessionID = message.slice( offset, len );
		offset += len;

		cipherSuite = message.getU16( offset ); 
		offset += 2;

		compressionMethod = message.get( offset );
		MUST( compressionMethod == 0, Alert.ILLEGAL_PARAMETER );
		offset++;

		this.extensions = TlsHelloClient.parseExtensions( message, offset );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary toBin()
	{
		Binary b = new Binary().reserve( 64 );
		b.addU16( protocol );
		b.add( random );
		b.add( sessionID.size() );
		b.add( sessionID );
		b.addU16( cipherSuite );
		b.add( compressionMethod ); // compression method
		TlsHelloClient.addExtensions( b, extensions );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append( "          SERVER HELLO:\n" );
		sb.append( String.format( "               version:  %04X (%s)\n", protocol, Protocol.toStr( protocol ) ) );
		sb.append(                "                random:  " + random.Hex() + "\n" );
		sb.append(                "             sessionId:  " + sessionID.Hex() + "\n");
		sb.append( String.format( "           cipherSuite:  %04X (%s)\n", cipherSuite, CipherSuite.toStr( cipherSuite ) ) );
		sb.append(                "            extensions:\n" );
		for( Map.Entry<Integer, Binary> entry : extensions.entrySet() )
		{
			sb.append( String.format( "                         type:  %04X (%s),  data:  %s\n",
					entry.getKey(), Extension.toStr( entry.getKey() ), entry.getValue().Hex() ) );
		}
		return sb.toString();
	}
}
