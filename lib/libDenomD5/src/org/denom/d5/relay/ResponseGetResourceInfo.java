// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5.relay;

import org.denom.Binary;
import org.denom.format.*;

/**
 * Ответ на команду GET RESOURCE INFO.
 */
public final class ResponseGetResourceInfo implements IBinable
{
	/**
	 * Идентификатор, выделенный Relay-ем для данного ресурса.
	 * Используя этот идентификатор, User может отправлять данные.
	 */
	public long resourceHandle = 0;

	/**
	 * Публичный ключ ресурса. [32 байта]
	 */
	public Binary resourcePublicKey = new Binary();

	/**
	 * Имя Resource-а, задаётся ресурсом произвольно.
	 */
	public String resourceName = "";

	/**
	 * JSON-строка с произвольным описанием ресурса.
	 */
	public String resourceDescription = "";

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализация для отправки ответа на команду GET RESOURCE INFO.
	 */
	@Override
	public Binary toBin()
	{
		BinBuilder bb = new BinBuilder();
		bb.append( resourceHandle );
		bb.append( resourcePublicKey );
		bb.append( resourceName );
		bb.append( resourceDescription );
		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Десериализация структуры при получении её User-ом.
	 */
	@Override
	public IBinable fromBin( final Binary bin, int offset )
	{
		BinParser parser = new BinParser( bin, offset );
		resourceHandle = parser.getLong();
		resourcePublicKey = parser.getBinary();
		resourceName = parser.getString();
		resourceDescription = parser.getString();
		return this;
	}
}
