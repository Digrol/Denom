// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5.relay;

import org.denom.Binary;
import org.denom.format.*;

/**
 * Ответ на команду WHO ARE YOU.
 */
public final class ResponseWhoAreYou implements IBinable
{
	/**
	 * Публичный ключ ресурса. [32 байта]
	 */
	public Binary resourcePublicKey;

	/**
	 * 16 байт случайных данных сгенерированных на ресурсе для формирования подписей сторон.
	 */
	public Binary resourceRandom;

	/**
	 * Подпись ресурса для аутентификации его на Relay.
	 */
	public Binary resourceSign;

	/**
	 * Имя Resource-а, задаётся ресурсом произвольно.
	 * Relay ограничивает размер принимаемой строки. Обычно - 256 символов.
	 */
	public String resourceName;
	
	/**
	 * JSON-строка с произвольным описанием ресурса.
	 * Relay ограничивает размер принимаемой строки. Обычно - 1024 символа.
	 */
	public String resourceDescription;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализация для отправки ответа на команду WHO_ARE_YOU.
	 */
	@Override
	public Binary toBin()
	{
		BinBuilder bb = new BinBuilder();
		bb.append( resourcePublicKey );
		bb.append( resourceRandom );
		bb.append( resourceSign );
		bb.append( resourceName );
		bb.append( resourceDescription );
		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Десериализация структуры при получении её на Relay.
	 */
	@Override
	public IBinable fromBin( final Binary bin, int offset )
	{
		BinParser parser = new BinParser( bin, offset );
		resourcePublicKey = parser.getBinary();
		resourceRandom = parser.getBinary();
		resourceSign = parser.getBinary();
		resourceName = parser.getString();
		resourceDescription = parser.getString();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конкатенация данных для передачи в алгоритм подписывания.
	 */
	public Binary formDataForSign( final Binary relayPublicKey, final Binary relayRandom )
	{
		Binary data = new Binary().reserve( 32 + 16 + 32 + 16 + this.resourceName.length() + this.resourceDescription.length() );
		data.add( relayPublicKey );
		data.add( relayRandom );
		data.add( this.resourcePublicKey );
		data.add( this.resourceRandom );
		data.add( new Binary().fromUTF8( this.resourceName ) );
		data.add( new Binary().fromUTF8( this.resourceDescription ) );
		return data;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычисляем подпись ресурса для аутентификации его на Relay.
	 * Метод прописывает соответствующие поля структуры: resourcePublicKey, randomResource, resourceSign
	 * @param relayPublicKey - публичный ключ Relay-а.
	 * @param relayRandom - случайка, сформированная на Relay-е.
	 * @param signerResource - Алгоритм с приватным и публичным ключом ресурса.
	 */
	public void sign( final Binary relayPublicKey, final Binary relayRandom, RelaySigner signerResource )
	{
		resourcePublicKey = signerResource.getPublicKey().clone();
		resourceRandom = new Binary().randomSecure( 16 );
		resourceSign = signerResource.sign( formDataForSign( relayPublicKey, relayRandom ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверяем подпись при получении этого ответа на Relay-е.
	 * @param relayPublicKey - публичный ключ Relay-а.
	 * @param relayRandom - случайка, сформированная на Relay-е.
	 */
	public boolean verifySign( final Binary relayPublicKey, final Binary relayRandom )
	{
		Binary data = formDataForSign( relayPublicKey, relayRandom );

		RelaySigner verifier = new RelaySigner();
		verifier.setPublicKey( resourcePublicKey );
		boolean isOk = verifier.verify( data, resourceSign );
		return isOk;
	}
}
