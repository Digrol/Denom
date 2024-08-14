// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5.relay;

import org.denom.Binary;
import org.denom.format.*;

/**
 * Информация о контакте, с которым взаимодействуем через Relay.
 */
public final class RelayContact implements IBinable
{
	/**
	 * Публичный ключ [RelaySigner.PUBLIC_KEY_SIZE]
	 * Уникальный идентификатор контакта.
	 */
	private Binary publicKey = new Binary();

	/**
	 * Имя контакта. Не обязательно уникальное.
	 */
	private String name = "";

	/**
	 * Комментарий о контакте.
	 */
	public String comment = "";

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Все поля пустые. Для последующей инициализации
	 */
	public RelayContact() {}

	// -----------------------------------------------------------------------------------------------------------------
	public RelayContact( final Binary publicKey, String name, String comment )
	{
		this.publicKey = publicKey.clone();
		this.name = name;
		this.comment = comment;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Reference, NOT a copy.
	 */
	public Binary getPublicKey()
	{
		return publicKey;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public String getName()
	{
		return name;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void setName( String name )
	{
		this.name = name;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public String getComment()
	{
		return comment;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public JSONObject toJSON()
	{
		JSONObject jo = new JSONObject();
		jo.put( "Public Key", publicKey );
		jo.put( "Name", name );
		jo.put( "Comment", comment );
		return jo;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return this
	 */
	public RelayContact fromJSON( JSONObject jo )
	{
		publicKey = jo.getBinary( "Public Key", RelaySigner.PUBLIC_KEY_SIZE );
		name = jo.getString( "Name" );
		comment = jo.getString( "Comment" );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary toBin()
	{
		Binary buf = new Binary().reserve( publicKey.size() + name.length() + comment.length() + 12 );
		BinBuilder bb = new BinBuilder( buf );
		bb.append( publicKey );
		bb.append( name );
		bb.append( comment );
		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public IBinable fromBin( Binary bin, int offset )
	{
		BinParser bp = new BinParser( bin, offset );
		publicKey = bp.getBinary();
		name = bp.getString();
		comment = bp.getString();
		return this;
	}
}
