// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.d5.relay;

import org.denom.*;
import org.denom.crypt.ec.ECAlg;
import org.denom.crypt.ec.Fp.custom.Secp256r1;
import org.denom.crypt.hash.*;
import org.denom.format.JSONObject;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * Класс для подписывания и проверки подписи под структурами Relay.
 * Все постоянные (статические) ключевые пары для Relay и клиентов должны генерироваться такими, что публичный ключ в сжатом виде имеет
 * первый байт = 02. Это даёт возможность хранить 32 байта (только координата X точки Q на кривой), а не 33 байта.
 */
public class RelaySigner
{
	/**
	 * Размер публичного ключа в байтах.
	 */
	public static final int PUBLIC_KEY_SIZE = 32;

	private ECAlg signAlg = new ECAlg( new Secp256r1() );
	private IHash hashAlg = new SHA256();

	private Binary publicKey;
	private Binary privateKey;

	// -----------------------------------------------------------------------------------------------------------------
	public RelaySigner() {}

	// -----------------------------------------------------------------------------------------------------------------
	public RelaySigner clone()
	{
		RelaySigner copy = new RelaySigner();
		if( privateKey != null )
		{
			copy.setPrivateKey( this.privateKey );
		}
		else if( publicKey != null )
		{
			copy.setPublicKey( publicKey );
		}
		return copy;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ECAlg getAlgorithm()
	{
		return signAlg;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Only X coord of point Q.
	 */
	public RelaySigner setPublicKey( final Binary pubKey )
	{
		MUST( pubKey.size() == 32, "PublicKey length != 32" );
		signAlg.setPublic( Bin( Bin("02"), pubKey ) );
		this.publicKey = pubKey.clone();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public RelaySigner setPrivateKey( final Binary privKey )
	{
		signAlg.setPrivate( privKey );
		this.privateKey = privKey.clone();

		Binary pubKey = signAlg.getPublic();
		MUST( pubKey.get( 0 ) == 0x02, "Incorrect privateKey for RelaySigner (not 02 in public)" );
		this.publicKey = pubKey.slice( 1, 32 );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Return publicKey reference.
	 */
	public Binary getPublicKey()
	{
		MUST( this.publicKey != null, "RelaySigner publicKey not set" );
		return this.publicKey;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Return privateKey reference.
	 */
	public Binary getPrivateKey()
	{
		MUST( this.privateKey != null, "RelaySigner privateKey not set" );
		return this.privateKey;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Генерируем ключевую пару такую, чтобы в публичном ключе (точке Q на кривой), координата Y была положительной.
	 */
	public RelaySigner generateKeyPair()
	{
		Binary pubKey;
		do
		{
			signAlg.generateKeyPair();
			this.privateKey = signAlg.getPrivate();
			pubKey = signAlg.getPublic();
		}
		while( pubKey.get( 0 ) != 0x02 );

		this.publicKey = pubKey.slice( 1, 32 );

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public synchronized Binary sign( final Binary data )
	{
		return signAlg.signECDSA( hashAlg.calc( data ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public synchronized boolean verify( final Binary data, final Binary sign )
	{
		return signAlg.verifyECDSA( hashAlg.calc( data ), sign );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param jo <pre> 
	 * В объекте jo должны присутствовать поля:
	 * {
	 *     "Algorithm": "EC_Secp256r1",
	 *     "Public":  "39C1..86BE",  <- 32 байта  Только X-координата, причём Y - всегда положительный, т.к. только такие ключевые пары генерируем
	 *     "Private": "2F4D..09АF"   <- 32 байта
	 * }</pre>
	 */
	public void readPrivateKeyFromJSON( final JSONObject jo )
	{
		String algStr = jo.getString( "Algorithm" );
		MUST( algStr.equalsIgnoreCase( "EC_Secp256r1" ), "Wrong algorithm, expected: EC_Secp256r1, have: " + algStr );
		Binary privKey = jo.getBinary( "Private", 32 );
		this.setPrivateKey( privKey );

		// Если публичный ключ хранится в JSON-е вместе с приватным, проверим, что он корректный 
		Binary pubKey = jo.optBinary( "Public", null );
		if( pubKey != null )
		{
			MUST( pubKey.size() == 32, "PublicKey length != 32" );
			MUST( pubKey.equals( this.publicKey ), "Incorrect publicKey" );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param jo <pre> 
	 * В объекте jo должны присутствовать поля:
	 * {
	 *     "Algorithm": "EC_Secp256r1",
	 *     "Public":  "39C1..86BE",  <- 32 байта  Только X-координата, причём Y - всегда положительный, т.к. только такие ключевые пары генерируем
	 * }</pre>
	 */
	public void readPublicKeyFromJSON( final JSONObject jo )
	{
		String algStr = jo.getString( "Algorithm" );
		MUST( algStr.equalsIgnoreCase( "EC_Secp256r1" ), "Wrong algorithm, expected: EC_Secp256r1, have: " + algStr );

		Binary pubKey = jo.getBinary( "Public" );
		MUST( pubKey.size() == 32, "PublicKey length != 32" );
		this.setPublicKey( pubKey );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void writePrivateKeyToJSON( JSONObject jo )
	{
		jo.put( "Algorithm", "EC_Secp256r1" );
		jo.put( "Private", getPrivateKey() );
		jo.put( "Public", getPublicKey() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void writePublicKeyToJSON( JSONObject jo )
	{
		jo.put( "Algorithm", "EC_Secp256r1" );
		jo.put( "Public", getPublicKey() );
	}
}
