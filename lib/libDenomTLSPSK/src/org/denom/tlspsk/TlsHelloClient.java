// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.tlspsk;

import java.util.*;
import org.denom.*;

import static org.denom.Ex.MUST;
import static org.denom.tlspsk.TlsConst.*;

public class TlsHelloClient
{
	public int protocol; // TLS Version
	public Binary random;
	public Binary sessionID;
	public Arr<Integer> cipherSuites;
	public Map<Integer, Binary> extensions;

	// -----------------------------------------------------------------------------------------------------------------
	public TlsHelloClient( int protocol, Binary random, Binary sessionID, Arr<Integer> cipherSuites,
			Map<Integer, Binary> extensions )
	{
		MUST( (random != null) && (sessionID != null) && (cipherSuites != null) && (extensions != null), "Wrong ClientHello params" );
		MUST( (protocol >= Protocol.TLSv1_0) && (protocol <= Protocol.TLSv1_2 ), Alert.ILLEGAL_PARAMETER );

		this.protocol = protocol;
		this.random = random;
		this.sessionID = sessionID;
		this.cipherSuites = cipherSuites;
		this.extensions = extensions;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TlsHelloClient( Binary message )
	{
		protocol = message.getU16( 0 );
		random = message.slice( 2, 32 );
		
		int offset = 2 + 32;
		int len = message.get( offset );
		offset += 1;
		sessionID = message.slice( offset, len );
		offset += len;

		len = message.getU16( offset );
		offset += 2;
		MUST( (len >= 2) && ((len & 1) == 0) && ((offset + len) <= message.size()) );

		int end = offset + len;
		cipherSuites = new Arr<>();
		while( offset < end )
		{
			cipherSuites.add( message.getU16( offset ) );
			offset += 2;
		}

		MUST( message.getU16( offset ) == 0x0100 ); // compression method
		offset += 2;

		this.extensions = parseExtensions( message, offset );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary toBin()
	{
		Binary b = new Binary().reserve( 64 );

		b.addU16( protocol ); // client_version

		b.add( random );  // [unix_time + random]

		b.add( sessionID.size() ); // <len8>
		b.add( sessionID ); // session_id

		// cipher_suites
		b.addU16( cipherSuites.size() * 2 ); // <len16>
		for( int suite : cipherSuites )
			b.addU16( suite );

		b.add( 1 ); // <len8>
		b.add( 0 ); // CompressionMethod = no compression

		addExtensions( b, extensions );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append( "          CLIENT HELLO:\n" );
		sb.append( String.format( "               version:  %04X (%s)\n", protocol, Protocol.toStr( protocol ) ) );
		sb.append(                "                random:  " + random.Hex() + "\n" );
		sb.append(                "             sessionId:  " + sessionID.Hex() + "\n");
		sb.append(                "          cipherSuites:\n" );
		for( int suite : cipherSuites )
			sb.append( String.format( "                         %04X (%s)\n", suite, CipherSuite.toStr( suite ) ) );

		sb.append(                "            extensions:\n" );
		for( Map.Entry<Integer, Binary> entry : extensions.entrySet() )
		{
			sb.append( String.format( "                         type:  %04X (%s),  data:  %s\n",
					entry.getKey(), Extension.toStr( entry.getKey() ), entry.getValue().Hex() ) );
		}
		return sb.toString();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Serialize extensions Map to Binary buffer.
	 */
	static void addExtensions( Binary buf, Map<Integer, Binary> extensions )
	{
		if( extensions.isEmpty() )
			return;

		int lenOffset = buf.size();
		buf.addU16( 0 ); // for total len

		for( Map.Entry<Integer, Binary> entry : extensions.entrySet() )
		{
			buf.addU16( entry.getKey() ); // extension Type
			buf.addU16( entry.getValue().size() ); // data size
			buf.add( entry.getValue() ); // data
		}

		buf.setU16( lenOffset, buf.size() - lenOffset - 2 ); // all extensions len
	}

	// -----------------------------------------------------------------------------------------------------------------
	static Map<Integer, Binary> parseExtensions( Binary buf, int offset )
	{
		Map<Integer, Binary> extensions = new HashMap<>();
		if( offset >= buf.size() )
			return extensions;

		int len = buf.getU16( offset );
		offset += 2;

		while( offset < buf.size() )
		{
			int extType = buf.getU16( offset );
			offset += 2;
			len = buf.getU16( offset );
			offset += 2;

			Binary extData = buf.slice( offset, len );
			MUST( extensions.put( extType, extData ) == null, TlsConst.Alert.ILLEGAL_PARAMETER, "Duplicate extension" );
			offset += len;
		}

		return extensions;
	}
}
