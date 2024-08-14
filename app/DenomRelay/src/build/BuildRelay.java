package build;

import org.denom.build.*;
import org.denom.log.*;

class BuildRelay
{
	public static void main( String[] args )
	{
		JarBuilder jb = new JarBuilder( new LogConsole(), "DenomRelay.jar" );
		jb.addDirectory( ".bin" );
		jb.addDirectory( "../../lib/libDenomCommon/.bin" );
		jb.addDirectory( "../../lib/libDenomD5/.bin" );
		jb.addDirectory( "../../lib/libDenomCrypt/.bin" );
		jb.addManifest( org.denom.net.d5.relay.RelayMain.class );
		jb.close();

		ProGuard pg = new ProGuard( new LogConsole(), "../../tools/proguard.jar" );
		pg.obfuscateJar( "DenomRelay.jar", ProGuard.paramsApp(), null );
	}
}
