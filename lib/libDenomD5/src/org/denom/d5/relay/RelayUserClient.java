// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5.relay;

import org.denom.*;
import org.denom.d5.*;
import org.denom.format.BinParser;

import static org.denom.Ex.MUST;

// ----------------------------------------------------------------------------------------------------------------
/**
 * Client to communicate with Denom Relay server as User.
 */
public class RelayUserClient extends D5Client
{
	public ResponseGetResourceInfo resourceInfo;

	private int indexUserResource = -1;
	protected RelaySM relaySM = null;

	// -----------------------------------------------------------------------------------------------------------------
	public RelayUserClient( String host, int port )
	{
		super( host, port );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Check if Resource present on Server.
	 * @return ResourceID or 0 if Resource absent/
	 */
	public ResponseGetResourceInfo cmdGetResourceInfo( final Binary resourcePublicKey )
	{
		Binary commandData = new Binary().reserve( 36 );
		commandData.addInt( resourcePublicKey.size() );
		commandData.add( resourcePublicKey );

		command( RelayCommand.GET_RESOURCE_INFO, commandData );

		this.resourceInfo = new ResponseGetResourceInfo();
		resourceInfo.fromBin( curResponse.data );
		indexUserResource = 1;

		return resourceInfo;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Начало защищенной сессии.
	 * @param userKey - Постоянный ключ пользователя
	 */
	public void sendInitSM( RelaySigner userKey )
	{
		MUST( this.resourceInfo != null, "Not connected to Resource" );

		RelaySM aRelaySM = new RelaySM( userKey );
		Binary data = aRelaySM.requestInitSM( this.resourceInfo.resourcePublicKey );
		Binary resp = cmdSend( RelayCommand.INIT_SM, data );
		aRelaySM.onResponseInitSM( resp );

		this.relaySM = aRelaySM;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * struct RequestSend
	 * {
	 *     long resourceHandle;
	 *     int userCommandIndex;
	 *
	 *     int userToResourceIndex;
	 *     int CommandCodeToResource;
	 *     Binary data;
	 * }
	 * 
	 * struct ResponseSend
	 * {
	 *     long resourceHandle;
	 *     int commandIndex;
	 *
	 *     int userToResourceIndex;
	 *     int answerCode;
	 *     int status;
	 *     Binary data;
	 * }
	 */
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Отправить ресурсу с заданным ID команду внутри команды SEND.
	 * @return
	 */
	public Binary cmdSend( int CommandCodeToResource, final Binary data )
	{
		MUST( resourceInfo.resourceHandle != -1, "command SEND: Not connected to resource" );

		Binary commandData = new Binary().reserve( data.size() + 12 );

		commandData.addLong( resourceInfo.resourceHandle );
		commandData.addInt( 0 ); // 4-байтовое поле, в которое Relay занесет индекс команды

		commandData.addInt( indexUserResource );
		commandData.addInt( CommandCodeToResource );

		commandData.addInt( data.size() );
		commandData.add( data );

		command( RelayCommand.SEND, commandData );

		BinParser parser = new BinParser( curResponse.data );
		long handle = parser.getLong();
		MUST( handle == resourceInfo.resourceHandle, "SEND: Wrong handle in response" );
		parser.getInt(); // 4-байтовое поле для индекса команды

		int index = parser.getInt();
		MUST( indexUserResource == index, "SEND: Wrong index in response" );

		int answerCode = parser.getInt();
		MUST( (answerCode + 0x20000000) == CommandCodeToResource, "SEND: Wrong Answer Code" );

		int status = parser.getInt();
		if( status != D5Response.STATUS_OK )
		{
			throw new Ex( status, parser.getString() );
		}

		Binary respData = parser.getBinary();

		indexUserResource++;

		return respData;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Отправить ресурсу с заданным ID зашифрованную команду внутри команды SEND.
	 * struct RequestSend
	 * {
	 *     long resourceHandle;
	 *     int userCommandIndex;
	 *
	 *     int userToResourceIndex;
	 *     Binary cryptogram; //  Encrypted( CommandCodeToResource | data )
	 *     Binary ccs;
	 * }
	 * @return
	 */
	public Binary cmdSendEncrypted( int CommandCodeToResource, final Binary data )
	{
		MUST( resourceInfo.resourceHandle != -1, "command SEND: Not connected to resource" );
		MUST( relaySM != null, "SM Error: Not initialized" );

		Binary commandData = new Binary().reserve( data.size() + 12 );

		commandData.addLong( resourceInfo.resourceHandle );
		commandData.addInt( 0 ); // 4-байтовое поле, в которое Relay занесет индекс команды

		commandData.addInt( indexUserResource );

		Binary encrypted = relaySM.encryptRequest( indexUserResource, CommandCodeToResource, data );
		commandData.add( encrypted );

		command( RelayCommand.SEND_ENCRYPTED, commandData );

		BinParser parser = new BinParser( curResponse.data );
		long handle = parser.getLong();
		MUST( handle == resourceInfo.resourceHandle, "SEND: Wrong handle in response" );
		parser.getInt(); // 4-байтовое поле для индекса команды

		int index = parser.getInt();
		MUST( indexUserResource == index, "SEND: Wrong index in response" );

		Int answerCode = new Int();
		Int status = new Int();
		Binary respData = relaySM.decryptResponse( indexUserResource, parser, answerCode, status );

		MUST( (answerCode.val + 0x20000000) == CommandCodeToResource, "SEND: Wrong Answer Code" );

		if( status.val != D5Response.STATUS_OK )
		{
			String msg = respData.asUTF8();
			throw new Ex( status.val, msg );
		}

		indexUserResource++;

		return respData;
	}

}