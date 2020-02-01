// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.testcrypt.hash;

import java.security.*;

import org.denom.crypt.hash.IHash;
import org.denom.*;
import org.denom.log.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.*;

/**
 * Функции для тестирования алгоритмов хеширования.
 */
class TestHashCommon
{
	// -----------------------------------------------------------------------------------------------------------------
	static void checkMsgHash( IHash hashAlg, String messageString, String hashHex )
	{
		Binary msg = Bin( messageString.getBytes() );
		Binary hash = hashAlg.calc( msg );
		MUST( hash.equals( hashHex ), "Check hash failed: " + hashAlg.name() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void checkHash( IHash hashAlg, Binary data, String hashHex )
	{
		MUST( hashAlg.calc( data ).equals( hashHex ), "Check hash failed: " + hashAlg.name() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void checkHash( IHash hashAlg, String messageHex, String hashHex )
	{
		Binary hash = hashAlg.calc( Bin( messageHex ) );
		MUST( hash.equals( hashHex ), "Check hash failed: " + hashAlg.name() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static void check1millionA( IHash hashAlg, String hashHex )
	{
		hashAlg.reset();
		Binary bin = new Binary( 1, 'a' );
		for( int i = 0; i < 1000000; ++i )
		{
			hashAlg.process( bin );
		}
		MUST( hashAlg.getHash().equals( hashHex ), "Million 'a' hash check failed" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * slsAlg должен вычислять такой же хеш, как алгоритм algName в стандартном крипто-провайдере.
	 */
	static void crossCheckStd( IHash slsAlg, String algName, ILog log )
	{
		log.write( "Cross check vs. '" + algName + "'... " );

		JavaHash javaHash = new JavaHash( algName );
		for( int i = 0; i < 1000; ++i )
		{
			Binary data = Bin().random( i );
			MUST( slsAlg.calc( data ).equals(  javaHash.calc( data )  ), "Cross check failed " + algName );
		}

		log.writeln( "OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * IHash.process(), обрабатывая входные данные по частям даёт тот же результат, что и IHash.calc,
	 * а также совпадает со стандартным алгоритмом. 
	 */
	static void checkStream( IHash slsAlg, String algName, ILog log )
	{
		log.write( "Stream check '" + algName + "'... " );

		JavaHash javaHash = new JavaHash( algName );
		for( int i = 0; i < 100 * 3; i += 3 )
		{
			Binary testdata = Bin().random( 100 * 3 );

			slsAlg.reset();
			slsAlg.process( testdata.slice( 0, i ) );
			slsAlg.process( testdata.slice( i, 3 ) );
			slsAlg.process( Bin() );
			slsAlg.process( testdata.slice( i + 3, 99 * 3 - i ) );

			MUST( slsAlg.getHash().equals(  javaHash.calc( testdata )  ), "Stream hash check failed: " + algName );
		}

		log.writeln( "OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	// Сравнение скорости вычисления хеша
	static void compareSpeed( IHash slsAlg, String algName, ILog log )
	{
		log.writeln( "Compare hash speed for '" + algName + "', 1000 x 50KB data: " );

		Binary data = Bin().random( 50 * 1024 );

		try
		{
			JavaHash javaHash = new JavaHash( algName );
			
			long tMs = Ticker.measureMs( 1000, () -> javaHash.calc( data ) );
			log.writeln( "  Std " + algName + " (1000): " + tMs + " ms" );
			log.writeln( "    " + data.size() * 1000 / 1024 / tMs + " MB/sec" );
		}
		catch( Throwable ex )
		{
			log.writeln( "  Std " + algName + ": Absent" );
		}
		

		long tMs = Ticker.measureMs( 1000, () -> slsAlg.calc( data ) );
		log.writeln( "  SLS " + algName + " (1000): " + tMs + " ms" );
		log.writeln( "    " + data.size() * 1000 / 1024 / tMs + " MB/sec" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	static class JavaHash
	{
		private MessageDigest digest;

		JavaHash( String algName )
		{
			try
			{
				digest = MessageDigest.getInstance( algName );
			}
			catch( Exception ex )
			{
				THROW( "No algorithm " + algName );
			}
		}

		Binary calc( Binary data )
		{
			digest.update( data.getDataRef(), 0, data.size() );
			return new Binary( digest.digest() );
		}
	}
}