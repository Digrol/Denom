// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5.relay;

import org.denom.*;
import org.denom.crypt.*;
import org.denom.crypt.ec.ECDSA;
import org.denom.crypt.hash.SHA256;
import org.denom.format.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * Secure Messaging между User-ом и Resource-ом.
 * Шифрование/расшифровывание команд.
 */
public class RelaySM
{
	private final RelaySigner myStaticKey;
	private ECDSA myEphemeralKey;
	public Binary otherStaticPublic;

	// Сессионные ключи
	private AES sessionKeyRequestEncrypt;
	private AES sessionKeyRequestCCS;
	private AES sessionKeyResponseEncrypt;
	private AES sessionKeyResponseCCS;
	public Binary iv;

	// -----------------------------------------------------------------------------------------------------------------
	public RelaySM( RelaySigner myStaticKey )
	{
		this.myStaticKey = myStaticKey.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Метод для User-а.
	 * Генерирует данные для запроса на инициализацию SM с Ресурсом - данные команды SEND__INIT_SM.
	 * @param otherPublicKey - без байта 02 или 03 вначале.
	 * @return <pre>
	 * struct RequestSendInitSM
	 * {
	 *     Binary userStaticPublicKey;
	 *     Binary userEphemeralPublicKey;
	 * }</pre>
	 */
	public Binary requestInitSM( final Binary otherPublicKey )
	{
		MUST( myEphemeralKey == null, "SM already inited" );
		
		this.otherStaticPublic = Bin( Bin("02"), otherPublicKey );

		BinBuilder bb = new BinBuilder();
		bb.append( myStaticKey.getPublicKey() );

		// Временная ключевая пара для генерации сессионного секрета
		myEphemeralKey = myStaticKey.getAlgorithm().clone();
		myEphemeralKey.generateKeyPair();
		Binary pubKey = myEphemeralKey.getPublic();
		bb.append( pubKey );

		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Генерация общего секрета и сессионных ключей.
	 */
	private void generateSessionKeys( final Binary otherEphemeralPublic )
	{
		Binary ecdh = myStaticKey.getAlgorithm().calcECDHCUnified( myEphemeralKey, otherStaticPublic, otherEphemeralPublic );

		SHA256 hashAlg = new SHA256();

		Binary key = hashAlg.calc( Bin( ecdh, new Binary().fromUTF8( "requestencrypt" ) ) );
		sessionKeyRequestEncrypt = new AES( key );
		key = hashAlg.calc( Bin( ecdh, new Binary().fromUTF8( "requestccs" ) ) );
		sessionKeyRequestCCS = new AES( key );

		key = hashAlg.calc( Bin( ecdh, new Binary().fromUTF8( "encryptresponse" ) ) );
		sessionKeyResponseEncrypt = new AES( key );
		key = hashAlg.calc( Bin( ecdh, new Binary().fromUTF8( "ccsresponse" ) ) );
		sessionKeyResponseCCS = new AES( key );

		iv = hashAlg.calc( Bin( ecdh, new Binary().fromUTF8( "InitialVector" ) ) ).first( AES.BLOCK_SIZE );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Метод для Resource-а.
	 * Парсинг запроса от User-а на инициализацию SM-а
	 * @param requestData
	 * @return responseData
	 */
	public Binary parseRequestInitSM( final Binary requestData )
	{
		MUST( myEphemeralKey == null, "SM already inited" );

		BinParser parser = new BinParser( requestData );
		this.otherStaticPublic = Bin( Bin("02"), parser.getBinary() );
		Binary otherEphemeralPublic = parser.getBinary();

		// Временная ключевая пара для генерации сессионного секрета
		myEphemeralKey = myStaticKey.getAlgorithm().clone();
		myEphemeralKey.generateKeyPair();

		generateSessionKeys( otherEphemeralPublic );

		BinBuilder bb = new BinBuilder();
		bb.append( myEphemeralKey.getPublic() );
		return bb.getResult();
	}

	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Метод для User-а.
	 * Парсинг ответа от ресурса на команду INIT SM.
	 * @param resp<pre>
	 * struct ResponseSendInitSM
	 * {
	 *     Binary resourceEphemeralPublicKey;
	 * }</pre>
	 */
	public void onResponseInitSM( final Binary resp )
	{
		MUST( myEphemeralKey != null, "command INIT SM not called" );
		BinParser parser = new BinParser( resp );
		Binary otherEphemeralPublic = parser.getBinary();
		generateSessionKeys( otherEphemeralPublic );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сложить начальный IV и index.
	 */
	private Binary sumIV( int index )
	{
		Binary curIV = iv.clone();
		for( int i = 0; i < iv.size(); i = i + 4 )
		{
			int a = iv.getIntBE( i );
			iv.setInt( i, a + index );
		}
		return curIV;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные запроса.
	 * @return 2 сериализованных Binary: [Len]Crypt | [Len]CCS.
	 * Crypt = Encrypt( commandCode | commandData )
	 */
	public Binary encryptRequest( int commandIndex, int commandCode, final Binary commandData )
	{
		Binary data = Bin().reserve( 4 + commandData.size() );
		data.addInt( commandCode );
		data.add( commandData );

		Binary curIV = sumIV( commandIndex );
		Binary crypt = sessionKeyRequestEncrypt.encrypt( data, CryptoMode.CFB, AlignMode.BLOCK, curIV );
		Binary ccs = sessionKeyRequestCCS.calcCCS( crypt, AlignMode.BLOCK, CCSMode.CLASSIC, curIV );

		data.clear();
		data.reserve( crypt.size() + 4 + ccs.size() + 4 );
		data.addInt( crypt.size() );
		data.add( crypt );
		data.addInt( ccs.size() );
		data.add( ccs );
		return data;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные запроса.
	 * В commandDataBuf возвращаются расшифрованные данные запроса
	 * @return commandData
	 */
	public Binary decryptRequest( int userToResourceIndex, BinParser parser, Int commandCode )
	{
		Binary crypt = parser.getBinary();
		Binary ccs = parser.getBinary();
		
		Binary curIV = sumIV( userToResourceIndex );
		Binary myCCS = sessionKeyRequestCCS.calcCCS( crypt, AlignMode.BLOCK, CCSMode.CLASSIC, curIV );
		MUST( myCCS.equals( ccs ), "SM Error: Wrong CCS" );

		Binary openData = sessionKeyRequestEncrypt.decrypt( crypt, CryptoMode.CFB, AlignMode.BLOCK, curIV );
		MUST( openData.size() > 4, "SM Error: Wrong Data Len" );

		commandCode.val = openData.getIntBE( 0 );
		return openData.last( openData.size() - 4 );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать данные ответа.
	 * @return 2 сериализованных Binary: [Len]Crypt | [Len]CCS.
	 * Crypt = Encrypt( answerCode | status | responseData )
	 */
	public Binary encryptResponse( int commandIndex, int answerCode, int status, final Binary responseData )
	{
		Binary data = Bin().reserve( 8 + responseData.size() );
		data.addInt( answerCode );
		data.addInt( status );
		data.add( responseData );

		Binary curIV = sumIV( commandIndex );
		Binary crypt = sessionKeyResponseEncrypt.encrypt( data, CryptoMode.CFB, AlignMode.BLOCK, curIV );
		Binary ccs = sessionKeyResponseCCS.calcCCS( crypt, AlignMode.BLOCK, CCSMode.CLASSIC, curIV );

		data.clear();
		data.reserve( crypt.size() + 4 + ccs.size() + 4 );
		data.addInt( crypt.size() );
		data.add( crypt );
		data.addInt( ccs.size() );
		data.add( ccs );
		return data;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать данные ответа.
	 * @return responseData
	 */
	public Binary decryptResponse( int userToResourceIndex, BinParser parser, Int answerCode, Int status )
	{
		Binary crypt = parser.getBinary();
		Binary ccs = parser.getBinary();
		
		Binary curIV = sumIV( userToResourceIndex );
		Binary myCCS = sessionKeyResponseCCS.calcCCS( crypt, AlignMode.BLOCK, CCSMode.CLASSIC, curIV );
		MUST( myCCS.equals( ccs ), "SM Error: Wrong CCS" );

		Binary openData = sessionKeyResponseEncrypt.decrypt( crypt, CryptoMode.CFB, AlignMode.BLOCK, curIV );
		MUST( openData.size() >= 8, "SM Error: Wrong Data Len" );

		answerCode.val = openData.getIntBE( 0 );
		status.val = openData.getIntBE( 4 );
		return openData.last( openData.size() - 8 );
	}

}
