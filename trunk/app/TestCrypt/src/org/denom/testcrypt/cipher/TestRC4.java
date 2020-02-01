package org.denom.testcrypt.cipher;

import org.denom.crypt.blockcipher.*;

import org.denom.Binary;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

class TestRC4
{
	// -----------------------------------------------------------------------------------------------------------------
	void check( String keyHex, String dataHex, String cryptHex )
	{
		Binary data = Bin( dataHex );
		Binary crypt = Bin( cryptHex );
		Binary out = Bin( data.size() );

		RC4 cipher = new RC4();
		KeyParameter param = new KeyParameter( Bin(keyHex) );
		cipher.init( true, param );
		cipher.processBytes( data.getDataRef(), 0, data.size(), out.getDataRef(), 0 );
		MUST( Bin( out ).equals( cryptHex ) );

		cipher.init( false, param );
		cipher.processBytes( crypt.getDataRef(), 0, crypt.size(), out.getDataRef(), 0 );
		MUST( Bin( out ).equals( data ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	TestRC4()
	{
		check( "0123456789ABCDEF", "4e6f772069732074", "3afbb5c77938280d" );
		check( "0123456789ABCDEF", "68652074696d6520", "1cf1e29379266d59" );
		check( "0123456789ABCDEF", "666f7220616c6c20", "12fbb0c771276459" );

		System.out.println( getClass().getSimpleName() + ": OK" );
	}

	public static void main( String[] args )
	{
		new TestRC4();
	}
}
