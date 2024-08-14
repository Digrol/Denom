// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import java.nio.file.*;

import org.denom.*;

import static org.denom.Ex.*;

/**
 * Работа с PC/SC-ридерами.
 */
public class CardReaderPCSCNative extends CardReader
{
	String PATH_IN_JAR = "bin/CardReaderPCSCNativeJNI.dll";
	private String curReaderName = null;
	private boolean cardPowered = false;

	private static boolean dllLoaded = false;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Загрузка библиотеки по указанному пути на дисках.
	 * @param dllFilePath Например, Paths.get("../../~build/x64_Debug/CardReaderPCSCNativeJNI.dll")
	 * если путь пустой или null, то ищем библиотеку внутри jar-файлов, либо в каталогах PATH.
	 */
	public CardReaderPCSCNative( String path )
	{
		synchronized( CardReaderPCSCNative.class )
		{
			if( !dllLoaded )
			{
				if( (path != null) && !path.isEmpty() )
				{
					System.load( Paths.get( path ).toAbsolutePath().toString() );
				}
				else
				{
					// Проблема - не удаляет временную распакованную DLL, засоряет диск
					try
					{
						// Загрузка библиотеки из jar-файла. JAR, содержащий DLL, должен быть в classpath.
						Sys.loadLibraryFromJar( PATH_IN_JAR );
					}
					catch( Throwable ex )
					{
						// Загрузка библиотеки в зависимости от платформы. Библиотека ищется по каталогам, указанным в PATH.
						// Для Windows - попытается найти CardReaderPCSCNativeJNI.dll.
						System.loadLibrary( "CardReaderPCSCNativeJNI" );
					}
				}
				dllLoaded = true;
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String[] enumReaders()
	{
		return enumerateReaders();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void checkConnected()
	{
		MUST( curReaderName != null, "Not connected to reader" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public CardReaderPCSCNative connect( String readerName )
	{
		disconnect();
		connectNative( readerName.getBytes( Strings.UTF8 ) );
		curReaderName = readerName;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void disconnect()
	{
		powerOffImpl();
		disconnectNative();
		curReaderName = null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void openFileLog( String logFileName, boolean isLogApdu, boolean isLogTpdu )
	{
		openFileLogNative( logFileName.getBytes( Strings.UTF8 ), isLogApdu, isLogTpdu );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public boolean isCardPresent()
	{
		checkConnected();
		try
		{
			return isCardPresentNative();
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
			return waitCardPresentNative( timeoutSec );
		}
		catch( Throwable ex )
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
			return waitCardRemoveNative( timeoutSec );
		}
		catch( Throwable ex )
		{
			return false;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected Binary powerOnImpl()
	{
		powerOffImpl();
		checkConnected();

		byte[] atrArr = powerOnNative();
		Binary atr = new Binary( atrArr );

		cardPowered = true;
		return atr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	protected void powerOffImpl()
	{
		if( cardPowered )
		{
			powerOffNative();
			cardPowered = false;
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
		return curReaderName;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public RApdu transmit( CApdu capdu )
	{
		//MUST( cardPowered, "Card not powered" );

		if( isTransportLog )
		{
			transportLog.writeln( " -> " + capdu.toBin().Hex( 1, 8, 0, 0 ) );
		}

		byte[] rapduArr = transmitNative( capdu.toBin().getBytes() );

		if( isTransportLog )
		{
			transportLog.writeln( " <- " + new Binary( rapduArr ).Hex( 1, 8, 0, 0 ) );
		}

		return new RApdu( rapduArr );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public CardReaderChannel getCardChannel( int logicalChannel )
	{
		return new CardReaderChannel( this, logicalChannel );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void close()
	{
		disconnect();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private native void openFileLogNative( byte[] logFileName, boolean isLogApdu, boolean isLogTpdu );

	private static native String[] enumerateReaders();
	private native void connectNative( byte[] readerName );
	private native void disconnectNative();
	private native boolean isCardPresentNative();
	private native boolean waitCardPresentNative( int timeoutSec );
	private native boolean waitCardRemoveNative( int timeoutSec );
	private native void powerOffNative();
	private native byte[] powerOnNative();
	private native byte[] transmitNative( byte[] capdu );
}
