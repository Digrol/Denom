// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5.relay;

import java.util.*;

import org.denom.Binary;
import org.denom.format.*;

/**
 * Список контактов, с которыми взаимодействуем через Relay.
 */
public final class RelayContacts implements IBinable
{
	public Map<Binary, RelayContact> contacts = new HashMap<>();

	// -----------------------------------------------------------------------------------------------------------------
	public RelayContacts() {}

	// -----------------------------------------------------------------------------------------------------------------
	public RelayContacts( Iterable<RelayContact> contacts )
	{
		for( RelayContact contact : contacts )
			this.contacts.put( contact.getPublicKey(), contact );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public JSONArray toJSON()
	{
		JSONArray ja = new JSONArray();
		for( RelayContact contact : contacts.values() )
			ja.put( contact.toJSON() );
		return ja;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public RelayContacts fromJSON( JSONArray ja )
	{
		contacts.clear();
		for( int i = 0; i < ja.length(); ++i )
		{
			RelayContact contact = new RelayContact();
			contact.fromJSON( ja.getJSONObject( i ) );
			contacts.put( contact.getPublicKey(), contact );
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary toBin()
	{
		BinBuilder bb = new BinBuilder();
		bb.append( contacts.values() );
		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public IBinable fromBin( Binary bin, int offset )
	{
		BinParser bp = new BinParser( bin, offset );
		RelayContact[] arr = (RelayContact[])bp.getBinableArr( RelayContact[].class );
		for( RelayContact contact : arr )
			this.contacts.put( contact.getPublicKey(), contact );
		return this;
	}
}
