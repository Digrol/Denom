package org.denom.testcrypt.ec;

import java.security.SecureRandom;
import org.denom.log.*;
import org.denom.crypt.ec.Nat;

import static org.denom.Ex.*;


public class TestInterleave
{
	private static final SecureRandom R = new SecureRandom();


	public TestInterleave( ILog log )
	{
		log.write( getClass().getSimpleName() + "... " );

		testExpand8To16();
		testExpand16To32();
		testExpand32To64();
		testExpand64To128();

		log.writeln( Colors.GREEN_I, "OK" );
	}

	private void testExpand8To16()
	{
		for( int iteration = 0; iteration < 256; ++iteration )
		{
			int x = iteration | (R.nextInt() << 8);
			int expected = (int)referenceShuffle( x & 0xFFL );
			int actual = Nat.expand8to16( x );
			MUST( expected == actual );
		}
	}


	private static void testExpand16To32()
	{
		for( int iteration = 0; iteration < 1000; ++iteration )
		{
			int x = R.nextInt();
			int expected = (int)referenceShuffle( x & 0xFFFFL );
			int actual = Nat.expand16to32( x );
			MUST( expected == actual );
		}
	}


	private static void testExpand32To64()
	{
		for( int iteration = 0; iteration < 1000; ++iteration )
		{
			int x = R.nextInt();
			long expected = referenceShuffle( x & 0xFFFFFFFFL );
			long actual = Nat.expand32to64( x );
			MUST( expected == actual );
		}
	}


	private static void testExpand64To128()
	{
		for( int iteration = 0; iteration < 1000; ++iteration )
		{
			long x = R.nextLong();
			long expected = referenceShuffle( x );
			long[] actual = new long[ 9 ];
			int offset = iteration % 8;
			// NOTE: Implementation must overwrite existing values
			actual[ offset ] = R.nextLong();
			actual[ offset + 1 ] = R.nextLong();
			Nat.expand64To128( x, actual, offset );
			MUST( (expected & 0x5555555555555555L) == actual[ offset ] );
			MUST( ((expected >>> 1) & 0x5555555555555555L) == actual[ offset + 1 ] );
		}
	}


	private static long referenceShuffle( long x )
	{
		long result = 0, y = x >>> 32;
		for( int bit = 0; bit < 32; ++bit )
		{
			long selector = 1L << bit;
			result |= ((x & selector) << (bit));
			result |= ((y & selector) << (bit + 1));
		}
		return result;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestInterleave( new LogConsole() );
	}

}
