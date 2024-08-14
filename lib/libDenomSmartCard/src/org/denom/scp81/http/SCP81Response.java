// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.scp81.http;

import org.denom.Binary;

import static org.denom.Ex.MUST;

/**
 * Формирование HTTP-Response по стандарту GlobalPlatform, Amendment B. SCP81.
 * + ETSI 102.225, ETSI 102.226
 */
public class SCP81Response extends HttpResp
{
	// -----------------------------------------------------------------------------------------------------------------
	public SCP81Response()
	{
		addHeader( "X-Admin-Protocol", "globalplatform-remote-admin/1.0" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void addNextURI( String nextURI )
	{
		addHeader( "X-Admin-Next-URI", nextURI );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void addTargetApp( String targetApp )
	{
		addHeader( "X-Admin-Targeted-Application", targetApp );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static SCP81Response noContent()
	{
		SCP81Response resp = new SCP81Response();
		resp.setStatusLine( 204, "No Content" );
		return resp;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static SCP81Response OkRAM( Binary body )
	{
		MUST( !body.empty(), "Empty body in SCP81Response" );

		SCP81Response resp = new SCP81Response();
		resp.setStatusLine( 200, "OK" );
		resp.addHeader( "Content-Type", "application/vnd.globalplatform.card-content-mgt;version=1.0" );
		resp.addHeader( "Content-Length", String.valueOf( body.size() ) );
		resp.setBody( body );

		return resp;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static SCP81Response OkRFM( Binary body )
	{
		MUST( !body.empty(), "Empty body in SCP81Response" );

		SCP81Response resp = new SCP81Response();
		resp.setStatusLine( 200, "OK" );
		resp.addHeader( "Content-Type", "application/vnd.etsi.scp.command-data;version=1.0" );
		resp.addHeader( "Content-Length", String.valueOf( body.size() ) );
		resp.setBody( body );

		return resp;
	}

}

