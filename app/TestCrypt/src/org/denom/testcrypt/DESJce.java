// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.testcrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.denom.*;
import org.denom.crypt.*;

import static org.denom.Ex.*;
import static org.denom.Binary.*;

/**
 * DES от стандартного крипто-провайдера.
 */
public class DESJce
{
	public static final int KEY_SIZE = 8;
	public static final int BLOCK_SIZE = 8;

	// -----------------------------------------------------------------------------------------------------------------
	public DESJce()
	{
		setKey( Bin(8) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public DESJce( final Binary key )
	{
		setKey( key );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary encrypt( final Binary data, CryptoMode crypt_mode, AlignMode align_mode, final Binary iv )
	{
		try
		{
			Binary padded = Bin().reserve( data.size() + BLOCK_SIZE );
			padded.add( data );
			Crypt.pad( padded, BLOCK_SIZE, align_mode );

			String str = "DES";
			switch( crypt_mode )
			{
				case ECB: str += "/ECB/NoPadding"; break;
				case CBC: str += "/CBC/NoPadding"; break;
				case OFB: str += "/OFB/NoPadding"; break;
				case CFB: str += "/CFB/NoPadding"; break;
			}

			Cipher cipher = Cipher.getInstance( str );

			SecretKeySpec skey = new SecretKeySpec( key.getDataRef(), 0, key.size(), "DES" );
			IvParameterSpec ivSpec = new IvParameterSpec( iv.getDataRef(), 0, iv.size() );

			if( crypt_mode == CryptoMode.ECB )
			{
				cipher.init( Cipher.ENCRYPT_MODE, skey );
			}
			else
			{
				cipher.init( Cipher.ENCRYPT_MODE, skey, ivSpec );
			}

			return new Binary( cipher.doFinal( padded.getDataRef(), 0, padded.size() ) );
		}
		catch( Throwable ex )
		{
			MUST( false, "Wrong data for encrypt. " + ex.toString() );
		}
		
		return null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary decrypt( final Binary crypt, CryptoMode crypt_mode, AlignMode align_mode, final Binary iv )
	{
		try
		{
			String str = "DES";
			switch( crypt_mode )
			{
				case ECB: str += "/ECB/NoPadding"; break;
				case CBC: str += "/CBC/NoPadding"; break;
				case OFB: str += "/OFB/NoPadding"; break;
				case CFB: str += "/CFB/NoPadding"; break;
			}

			Cipher cipher = Cipher.getInstance( str );

			SecretKeySpec skey = new SecretKeySpec( key.getDataRef(), 0, key.size(), "DES" );
			IvParameterSpec ivSpec = new IvParameterSpec( iv.getDataRef(), 0, iv.size() );

			if( crypt_mode == CryptoMode.ECB )
			{
				cipher.init( Cipher.DECRYPT_MODE, skey );
			}
			else
			{
				cipher.init( Cipher.DECRYPT_MODE, skey, ivSpec );
			}

			Binary data = new Binary( cipher.doFinal( crypt.getDataRef(), 0, crypt.size() ) );
			Crypt.unPad( data, BLOCK_SIZE, align_mode );
			return data;
		}
		catch( Throwable ex )
		{
			MUST( false, "Wrong data for decrypt. " + ex.toString() );
		}
		
		return null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary encrypt( final Binary data, CryptoMode crypt_mode, AlignMode align_mode )
	{
		return encrypt( data, crypt_mode, align_mode, IV0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary decrypt( final Binary crypt, CryptoMode crypt_mode, AlignMode align_mode )
	{
		return decrypt( crypt, crypt_mode, align_mode, IV0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary calcCCS( final Binary data, AlignMode alignMode, CCSMode ccsMode, final Binary iv )
	{
		Binary padded = Bin().reserve( data.size() + BLOCK_SIZE );
		padded.add( data );
		Crypt.pad( padded, BLOCK_SIZE, alignMode );

		MUST( !padded.empty(), "No data" );
		MUST( iv.size() == BLOCK_SIZE, "Wrong IV length. Must be 8 bytes." );

		Binary crypt = encrypt( padded, CryptoMode.CBC, AlignMode.NONE, iv );
		return crypt.slice( crypt.size() - BLOCK_SIZE, BLOCK_SIZE );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary calcCCS( final Binary data, AlignMode alignMode, CCSMode ccsMode )
	{
		return calcCCS( data, alignMode, ccsMode, IV0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void setKey( final Binary key )
	{
		MUST( key.size() == KEY_SIZE, "Wrong key size" );
		this.key = key.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getKey()
	{
		return this.key.clone();
	}
	
	private Binary key;
	private static Binary IV0 = new Binary( BLOCK_SIZE );
}