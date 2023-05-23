// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5.relay;

import org.denom.*;
import org.denom.format.*;

import static org.denom.Ex.MUST;

/**
 * Формирует и парсит запросы и ответы для команд авторизации для соединения Relay-Resource.
 */
public class RelayAuth
{
	private RelaySigner myKey;
	private Binary relayRandom = null;
	private Binary relayPublicKey = null;
	
	ResponseWhoAreYou resourceInfo = null;

	// -----------------------------------------------------------------------------------------------------------------
	public RelayAuth( RelaySigner myKey )
	{
		this.myKey = myKey;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Метод для Relay-а.
	 * Сформировать запрос команды 'WHO ARE YOU' для подключившегося ресурса.
	 * <pre>
	 * struct RequestWhoAreYou
	 * {
	 *     Binary relayPublicKey;
	 *     Binary relayRandom;
	 * }</pre>
	 */
	public Binary requestWhoAreYou()
	{
		this.relayRandom = new Binary().randomSecure( 16 );

		BinBuilder bb = new BinBuilder();
		bb.append( myKey.getPublicKey() ); // 32 байта - публичный ключ Relay-а
		bb.append( relayRandom );  // 16 байт случайки
		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Метод для Resource-а.
	 * Обработка команды 'WHO ARE YOU' от Relay-а.
	 * Возвращает данные для ответа.
	 */
	public Binary onRequestWhoAreYou( final Binary commandData, String resourceName, String resourceDescription )
	{
		resourceInfo = null;

		BinParser parser = new BinParser( commandData );
		relayPublicKey = parser.getBinary();
		MUST( relayPublicKey.size() == 32, "Wrong relayPublicKey size" );
		relayRandom = parser.getBinary();
		MUST( relayRandom.size() == 16, "Wrong relayRandom size" );

		resourceInfo = new ResponseWhoAreYou();
		resourceInfo.resourceName = resourceName;
		resourceInfo.resourceDescription = resourceDescription;
		resourceInfo.sign( relayPublicKey, relayRandom, myKey );
		return resourceInfo.toBin();
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Метод для Relay-а.
	 * Распарсить ответ на команду 'WHO ARE YOU'. Проверить подпись ресурса.
	 */
	public ResponseWhoAreYou responseWhoAreYou( Binary resp )
	{
		// Получили от ресурса ответ на команду WHO ARE YOU, но Relay команду не посылал
		MUST( relayRandom != null, "Protocol Error: Got 'WHO ARE YOU' response" );

		this.resourceInfo = new ResponseWhoAreYou();
		resourceInfo.fromBin( resp );

		// Проверяем ограничения на размеры полей
		MUST( resourceInfo.resourcePublicKey.size() == 32,"Protocol Error: responseWhoAreYou: public key size != 32" );
		MUST( resourceInfo.resourceRandom.size() == 16, "Protocol Error: responseWhoAreYou: random size != 16" );

		MUST( resourceInfo.verifySign( myKey.getPublicKey(), relayRandom ), "Protocol Error: responseWhoAreYou: wrong sign" );

		return resourceInfo;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Метод для Relay-а.
	 * Сформировать запрос команды 'RELAY SIGN' с подписью Relay-а для отправки ресурсу. 
	 */
	public Binary requestRelaySign()
	{
		MUST( resourceInfo != null, "Protocol Error: send 'WHO ARE YOU' first" );

		Binary data = new Binary().reserve( 32 + 16 + 32 + 16 );
		data.add( myKey.getPublicKey() );
		data.add( this.relayRandom );
		data.add( this.resourceInfo.resourcePublicKey );
		data.add( this.resourceInfo.resourceRandom );

		Binary relaySign = myKey.sign( data );
		return relaySign;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void onRequestSignRelay( final Binary commandData )
	{
		MUST( relayPublicKey != null, "Protocol Error: got RELAY_SIGN command" );

		Binary data = new Binary().reserve( 32 + 16 + 32 + 16 );
		data.add( relayPublicKey );
		data.add( relayRandom );
		data.add( myKey.getPublicKey() );
		data.add( resourceInfo.resourceRandom );

		this.resourceInfo = null;
		this.myKey = null;

		Binary relaySign = commandData;

		RelaySigner relayVerifier = new RelaySigner();
		relayVerifier.setPublicKey( relayPublicKey );
		MUST( relayVerifier.verify( data, relaySign ), "Protocol Error: wrong relay Sign" );
	}

}
