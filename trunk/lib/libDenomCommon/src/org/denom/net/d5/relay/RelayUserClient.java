// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5.relay;

import org.denom.*;
import org.denom.net.d5.*;
import org.denom.format.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

// ----------------------------------------------------------------------------------------------------------------
/**
 * Client to work with Denom Relay server as User.
 */
public class RelayUserClient extends D5Client
{
	Binary curCommandData = Bin();
	
	// -----------------------------------------------------------------------------------------------------------------
	public RelayUserClient( String host, int port )
	{
		super( host, port );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Check if Resource present on Server.
	 * @return ResourceID or 0 if Resource 
	 */
	public long cmdIsResourcePresent( final String resourceName )
	{
		curCommandData.clear();
		byte[] arrName = resourceName.getBytes( Strings.UTF8 );
		curCommandData.addInt( arrName.length );
		curCommandData.add( arrName );

		command( RelayCmd.IS_RESOURCE_PRESENT, curCommandData );
		MUST( curResponse.data.size() == 8, "Wrong Response size on command 'isResourcePresent'" );
		return curResponse.data.getLong( 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Get list of Resources on server with names started with 'namePrefix'.
	 */
	public Arr<String> cmdListResources( String namePrefix )
	{
		command( RelayCmd.LIST_RESOURCES, Bin().fromUTF8( namePrefix ) );
		BinParser bp = new BinParser( curResponse.data );
		Arr<String> names = new Arr<String>();
		bp.getStringCollection( names );
		return names;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary cmdSend( long resourceID, final Binary data )
	{
		curCommandData.clear();
		curCommandData.reserve( data.size() + 12 );

		curCommandData.addLong( resourceID );

		curCommandData.addInt( 0 );

		curCommandData.addInt( data.size() );
		curCommandData.add( data );

		command( RelayCmd.SEND, curCommandData );

		MUST( curResponse.data.size() >= 16, "Wrong response on command 'Send'" );
		return curResponse.data.last( curResponse.data.size() - 16 );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public Binary cmdSendTo( String resourceName, final Binary data )
	{
		curCommandData.clear();
		curCommandData.reserve( data.size() + 4 + resourceName.length() * 2 );

		byte[] arrName = resourceName.getBytes( Strings.UTF8 );
		curCommandData.addInt( arrName.length );
		curCommandData.add( arrName );

		curCommandData.addInt( data.size() );
		curCommandData.add( data );

		command( RelayCmd.SEND_TO, curCommandData );

		MUST( curResponse.data.size() >= 16, "Wrong response on command 'SendTo'" );
		return curResponse.data.last( curResponse.data.size() - 16 );
	}
}