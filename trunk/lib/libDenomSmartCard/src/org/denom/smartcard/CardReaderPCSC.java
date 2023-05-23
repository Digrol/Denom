// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import java.util.List;
import javax.smartcardio.*;

import org.denom.Binary;

import static org.denom.Ex.*;

/**
 * Работа с PC/SC-ридерами.
 */
public class CardReaderPCSC extends CardReader
{
	// -----------------------------------------------------------------------------------------------------------------
	public CardReaderPCSC() {}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String[] enumReaders()
	{
		try
		{
			List<CardTerminal> terminals = factory.terminals().list();
			String[] names = new String[ terminals.size() ];
			for( int i = 0; i < terminals.size(); ++i )
			{
				names[ i ] = terminals.get( i ).getName();
			}
			return names;
		}
		catch( Throwable ex )
		{
			return new String[0];
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@SuppressWarnings("resource")
	public static String[] enumerateReaders()
	{
		return new CardReaderPCSC().enumReaders();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public CardReaderPCSC connect( String readerName )
	{
		disconnect();
		terminal = factory.terminals().getTerminal( readerName );
		MUST( terminal != null, "No such Card reader with name: " + readerName );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void disconnect()
	{
		powerOffImpl();
		terminal = null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public boolean isCardPresent()
	{
		checkConnected();
		try
		{
			return terminal.isCardPresent();
		}
		catch( Throwable ex )
		{
			return false;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public boolean waitCardPresent( int timeoutSec )
	{
		checkConnected();
		try
		{
			return terminal.waitForCardPresent( timeoutSec * 1000 );
		}
		catch( CardException ex )
		{
			return false;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public boolean waitCardRemove( int timeoutSec )
	{
		checkConnected();
		try
		{
			return terminal.waitForCardAbsent( timeoutSec * 1000 );
		}
		catch( CardException ex )
		{
			return false;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected Binary powerOnImpl()
	{
		powerOffImpl();
		checkCardInserted();

		try
		{
			card = terminal.connect( "*" );
			channel = card.getBasicChannel();
			ATR a = card.getATR();
			return new Binary( a.getBytes() );
		}
		catch( Throwable ex )
		{
			THROW( ex.toString() );
		}
		return new Binary();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected void powerOffImpl()
	{
		try
		{
			if( card != null )
			{
				channel = null;
				card.disconnect( true );
				card = null;
			}
		}
		catch( CardException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected Binary resetImpl()
	{
		powerOffImpl();
		return powerOnImpl();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String getName()
	{
		checkConnected();
		return terminal.getName();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public RApdu transmit( CApdu capdu )
	{
		MUST( channel != null, "Card not powered" );
		try
		{
			if( isTransportLog )
			{
				transportLog.writeln( "        Command APDU:" );
				transportLog.writeln( capdu.toBin().Hex( 1, 8, 16, 8 ) );
			}
			
			ResponseAPDU rapdu = channel.transmit( new CommandAPDU( capdu.toBin().getBytes() ) );
			
			if( isTransportLog )
			{
				transportLog.writeln( "        Response APDU:" );
				transportLog.writeln( new Binary( rapdu.getBytes() ).Hex( 1, 8, 16, 8 ) );
			}
			
			return new RApdu( rapdu.getBytes() );
		}
		catch( CardException ex )
		{
			MUST( false, ex.toString() );
		}
		return null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void close()
	{
		disconnect();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkConnected()
	{
		MUST( terminal != null, "Not connected to reader" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkCardInserted()
	{
		checkConnected();
		try
		{
			if( !terminal.isCardPresent() )
			{
				THROW( "Card not inserted in reader: '" + getName() + "'"  );
			}
		}
		catch( Throwable ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private CardChannel channel;
	private Card card;
	private CardTerminal terminal;
	private TerminalFactory factory = TerminalFactory.getDefault();
}
