// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.Binary;

/**
 * CardReader that does nothing.
 */
public class CardReaderNull extends CardReader
{
	public CardReaderNull() {}

	@Override
	public String[] enumReaders() { return new String[0]; }

	@Override
	public CardReader connect( String readerName ) { return this; }

	@Override
	public void disconnect() {}

	@Override
	public boolean isCardPresent() { return true; }

	@Override
	public boolean waitCardPresent( int timeoutSec ) { return true; }

	@Override
	public boolean waitCardRemove( int timeoutSec ){ return false; }
	
	@Override
	public Binary powerOnImpl() { return new Binary(); }

	@Override
	public void powerOffImpl() {}

	@Override
	public Binary resetImpl() { return new Binary(); }

	@Override
	public String getName() { return "CardReader NULL"; }

	@Override
	public RApdu transmit( CApdu capdu ) { return new RApdu(); }

	@Override
	public CardReader getCardChannel( int logicalChannel ) { return this; }

	@Override
	public void close() {}
}
