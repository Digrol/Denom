package org.denom.testcrypt.ec;

import java.security.*;
import java.security.spec.*;

import org.denom.format.BerTLVList;
import org.denom.Binary;

import static org.denom.Binary.Bin;
import static org.denom.Ex.*;

public class ECDSAStd
{
	PublicKey pubKey;
	PrivateKey privKey;

	// -----------------------------------------------------------------------------------------------------------------
	Signature signatureAlg;
	KeyPairGenerator keyPairGenerator;
	KeyFactory keyFactory;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Кривая - NIST P-256 curve (secp256r1).
	 */
	public ECDSAStd()
	{
		try
		{
			keyFactory = KeyFactory.getInstance( "EC" );
			keyPairGenerator = KeyPairGenerator.getInstance( "EC" );
			keyPairGenerator.initialize( new ECGenParameterSpec( "secp256r1" ) );
			signatureAlg = Signature.getInstance( "SHA256withECDSA" );
		}
		catch( Throwable ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Генерация ключевой пары EC.
	 * Кривая - NIST P-256 curve (secp256r1).
	 */
	public ECDSAStd generateKeyPair()
	{
		try
		{
			KeyPair pair = keyPairGenerator.generateKeyPair();
			pubKey = pair.getPublic();
			privKey = pair.getPrivate();
		}
		catch( Throwable ex )
		{
			THROW( ex.toString() );
		}
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return публичный ключ в формате X.509.
	 */
	public Binary getPublicKeyX509()
	{
		return Bin( pubKey.getEncoded() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return публичный ключ.
	 */
	public Binary getPublicKey()
	{
		BerTLVList l = new BerTLVList( Bin( pubKey.getEncoded() ) );
		Binary b = l.find( "30/03" ).value;
		b = b.last( b.size() - 1 );
		return b;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public void setPublicKeyX509( Binary publicKeyX509 )
	{
		try
		{
			pubKey = keyFactory.generatePublic( new X509EncodedKeySpec( publicKeyX509.getBytes() ) );
		}
		catch( InvalidKeySpecException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getPrivateKey()
	{
		BerTLVList l = new BerTLVList( Bin( privKey.getEncoded() ) );
		l.assign( l.find( "30/04" ).value );
		Binary b = l.find( "30/04" ).value;
		return b;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public Binary getPrivateKeyPKCS8()
	{
		return Bin( privKey.getEncoded() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void setPrivateKeyPKCS8( Binary privateKeyPKCS8 )
	{
		try
		{
			privKey = keyFactory.generatePrivate(  new PKCS8EncodedKeySpec( privateKeyPKCS8.getBytes() ) );
		}
		catch( InvalidKeySpecException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Подписать данные. Хэш - SHA256.
	 */
	public Binary sign( Binary data )
	{
		Binary sign = Bin();
		try
		{
			signatureAlg.initSign( privKey );
			signatureAlg.update( data.getBytes() );
			sign.assign( signatureAlg.sign() );
		}
		catch( Throwable ex )
		{
			THROW( ex.toString() );
		}

		return sign;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверить подпись.
	 */
	public boolean verify( Binary data, Binary sign )
	{
		try
		{
			signatureAlg.initVerify( pubKey );
			signatureAlg.update( data.getBytes() );
			return signatureAlg.verify( sign.getBytes() );
		}
		catch( Throwable ex )
		{
			THROW( ex.toString() );
		}
		return false;
	}

}
