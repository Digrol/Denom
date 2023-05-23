// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.gp;

import org.denom.*;
import org.denom.format.*;
import org.denom.card.CApdu;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

//-----------------------------------------------------------------------------------------------------------------
/**
 * Вычисление сессионных ключей для GP-домена от заданных ключей.
 */
public class SecurityModuleGPPlain implements ISecurityModuleGP
{
	public final Binary domainEnc = Bin();
	public final Binary domainMac = Bin();
	public final Binary domainDek = Bin();

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SecurityModuleGPPlain init( JSONObject jo )
	{
		THROW( "Not implemented" );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void connect() {}

	@Override
	public void disconnect() {}

	@Override
	public Binary generateMK( int keyId, Binary asn )
	{
		THROW( "Not implemented" );
		return null;
	}

	@Override
	public int rsaGetNLen()
	{
		THROW( "Not implemented" );
		return 0;
	}

	@Override
	public Binary rsaCryptPrivate( Binary data )
	{
		THROW( "Not implemented" );
		return null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary gpGenSmSessionKeys( int smMode, Binary hostChallenge, Binary initUpdateResponse )
	{
		GP_SM.SessionKeys sessionKeys = GP_SM.genSessionKeys( domainEnc, domainMac, domainDek, hostChallenge, initUpdateResponse );
		MUST( sessionKeys != null, "Wrong card cryptogram or incorrect domain keys" );
		CApdu ap = GP_SM.formExtAuth( initUpdateResponse, smMode, hostChallenge, sessionKeys, new GP_SM() );
		return Bin( sessionKeys.enc, sessionKeys.cmac, sessionKeys.rmac, sessionKeys.dek, ap.data.last( 8 ), ap.toBin() );
	}

}
