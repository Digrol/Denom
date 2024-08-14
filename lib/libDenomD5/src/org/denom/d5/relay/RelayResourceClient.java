// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5.relay;

import java.util.*;

import org.denom.*;
import org.denom.d5.*;
import org.denom.format.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;


// ----------------------------------------------------------------------------------------------------------------
/**
 * Client to work with Denom Relay server as Resource asynchronously.
 */
public abstract class RelayResourceClient extends D5ReverseClient
{
	public final RelaySigner resourceKey;
	public final String resourceName;
	public final String resourceDescription;

	private RelayAuth relayAuth;

	protected Map<Long, RelaySM> userSMSesions = new HashMap<>();

	// -----------------------------------------------------------------------------------------------------------------
	public RelayResourceClient( RelaySigner resourceKey, String resourceName, String resourceDescription,
		int numWorkerThreads, String prefixNameForThreads )
	{
		super( numWorkerThreads, prefixNameForThreads );
		this.resourceKey = resourceKey;
		this.resourceName = resourceName;
		this.resourceDescription = resourceDescription;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызывается в одном из рабочих потоков.
	 */
	@Override
	protected Binary onCommandDispatch( D5Command command )
	{
		switch( command.code )
		{
			// Эти команды инициирует Relay
			case D5Command.ENUM_COMMANDS     : return onCmdEnumCommands( command.data );
			case RelayCommand.WHO_ARE_YOU    : return onCmdWhoAreYou( command.data );
			case RelayCommand.RELAY_SIGN     : return onCmdRelaySign( command.data );
			// Эта команда отправляется через Relay от User-ов.
			case RelayCommand.SEND           : return onCmdSend( command );
			case RelayCommand.SEND_ENCRYPTED : return onCmdSendEncrypted( command.data );

			default:
				throw new Ex( D5Response.STATUS_COMMAND_NOT_SUPPORTED );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary onCmdEnumCommands( Binary commandBuf )
	{
		Binary b = Bin();
		b.addInt( D5Command.ENUM_COMMANDS );
		b.addInt( RelayCommand.WHO_ARE_YOU );
		b.addInt( RelayCommand.RELAY_SIGN );
		b.addInt( RelayCommand.SEND );
		b.addInt( RelayCommand.SEND_ENCRYPTED );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подписываем случайные данные и публичные ключи, чтобы аутентифицироваться на Relay-е.
	 */
	private Binary onCmdWhoAreYou( Binary commandData )
	{
		relayAuth = new RelayAuth( resourceKey );
		return relayAuth.onRequestWhoAreYou( commandData, resourceName, resourceDescription );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Команда от Relay с его подписью. Проверяем подпись.
	 */
	private Binary onCmdRelaySign( Binary commandData )
	{
		MUST( relayAuth != null, "Protocol Error: got RELAY_SIGN command" );
		relayAuth.onRequestSignRelay( commandData );
		return new Binary();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * User инициализирует SM.
	 * @return
	 */
	private Binary processInitSM( long userHandle, final Binary commandData )
	{
		RelaySM sm = null;
		synchronized( userSMSesions )
		{
			sm = userSMSesions.get( userHandle );
		}
		MUST( sm == null, "SM already inited" );

		sm = new RelaySM( resourceKey );

		Binary resp  = sm.parseRequestInitSM( commandData );

		synchronized( userSMSesions )
		{
			userSMSesions.put( userHandle, sm );
		}
		
		return resp;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * struct RequestSend
	 * {
	 *     long userHandle;
	 *     int userCommandIndex;
	 *     int userToResourceIndex;
	 *     int commandCodeToResource;
	 *     Binary data;
	 * }
	 * 
	 * struct ResponseSend
	 * {
	 *     long userHandle;
	 *     int commandIndex;
	 *     int userToResourceIndex;
	 *     int answerCode;
	 *     int status;
	 *     Binary data;
	 * }
	 */
	private Binary onCmdSend( D5Command command )
	{
		BinParser parser = new BinParser( command.data );
		long userHandle = parser.getLong();
		int userCommandIndex = parser.getInt();
		int userToResourceIndex = parser.getInt();
		int commandCode = parser.getInt();
		Binary commandData = parser.getBinary();

		// Обработка команды
		int status = D5Response.STATUS_OK;
		Binary dataToUser = Bin();

		try
		{
			if( commandCode == RelayCommand.INIT_SM )
			{
				dataToUser = processInitSM( userHandle, commandData );
			}
			else
			{
				dataToUser = dispatchSend( userHandle, userToResourceIndex, commandCode, commandData );
			}
		}
		catch( Ex ex )
		{
			status = D5Response.STATUS_UNKNOWN_ERROR;
			if( (ex.code & 0xE0000000) == 0xE0000000 )
			{
				status = ex.code;
			}
			dataToUser.fromUTF8( ex.getMessage() );
		}
		catch( Throwable ex )
		{
			status = D5Response.STATUS_UNKNOWN_ERROR;
			dataToUser.fromUTF8( ex.toString() );
		}

		// Формируем ResponseSend
		Binary buf = Bin().reserve( 28 + dataToUser.size() );
		BinBuilder bb = new BinBuilder( buf );
		bb.append( userHandle );
		bb.append( userCommandIndex );
		bb.append( userToResourceIndex );
		bb.append( commandCode - 0x20000000 ); // answerCode
		bb.append( status );
		bb.append( dataToUser );

		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * struct RequestSendEncrypted
	 * {
	 *     long userHandle;
	 *     int userCommandIndex;
	 *     int userToResourceIndex;
	 *     Binary crypt;
	 *     Binary ccs;
	 * }
	 * 
	 * struct ResponseSendEncrypted
	 * {
	 *     long userHandle;
	 *     int userCommandIndex;
	 *     int userToResourceIndex;
	 *     Binary crypt;
	 *     Binary ccs;
	 * }
	 */
	private Binary onCmdSendEncrypted( Binary commandBuf )
	{
		BinParser parser = new BinParser( commandBuf );
		long userHandle = parser.getLong();
		int userCommandIndex = parser.getInt();
		int userToResourceIndex = parser.getInt();

		RelaySM sm = null;
		synchronized( userSMSesions )
		{
			sm = userSMSesions.get( userHandle );
		}
		MUST( sm != null, "SM Error: not initialized" );

		Int commandCode = new Int();
		Binary commandData = sm.decryptRequest( userToResourceIndex, parser, commandCode );

		// Обработка команды
		int status = D5Response.STATUS_OK;
		Binary dataToUser = Bin();

		try
		{
			dataToUser = dispatchSend( userHandle, userToResourceIndex, commandCode.val, commandData );
		}
		catch( Ex ex )
		{
			status = D5Response.STATUS_UNKNOWN_ERROR;
			if( (ex.code & 0xE0000000) == 0xE0000000 )
			{
				status = ex.code;
			}
			dataToUser.fromUTF8( ex.getMessage() );
		}
		catch( Throwable ex )
		{
			status = D5Response.STATUS_UNKNOWN_ERROR;
			dataToUser.fromUTF8( ex.toString() );
		}

		// Формируем ResponseSend
		Binary resp = Bin().reserve( 60 + dataToUser.size() );
		resp.addLong( userHandle );
		resp.addInt( userCommandIndex );
		resp.addInt( userToResourceIndex );

		Binary encrypted = sm.encryptResponse( userToResourceIndex, commandCode.val - 0x20000000, status, dataToUser );
		resp.add( encrypted );

		return resp;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected abstract Binary dispatchSend( long userHandle, int userToResourceIndex, int commandCode, Binary data );

}