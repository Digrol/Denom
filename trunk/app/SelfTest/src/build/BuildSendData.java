package build;

import org.denom.build.*;
import org.denom.log.*;

class BuildSendData
{
	public static void main( String[] args )
	{
		ILog log = new LogConsole();
		JarBuilder jb = new JarBuilder( new LogConsole(), "SendData.jar" );
		jb.addDirectory( ".bin" );
		jb.addDirectory( "../../lib/libDenomCommon/.bin" );
		jb.addDirectory( "../../lib/libDenomRelay/.bin" );
		jb.addManifest( relay.SendData.class );
		jb.close();

		ProGuard pg = new ProGuard( log, "../../tools/proguard.jar" );
		pg.obfuscateJar( "SendData.jar", ProGuard.paramsApp(), null );
	}
}
