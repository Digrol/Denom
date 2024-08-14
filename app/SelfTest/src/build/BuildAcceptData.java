package build;

import org.denom.build.*;
import org.denom.log.*;

class BuildAcceptData
{
	public static void main( String[] args )
	{
		ILog log = new LogConsole();
		JarBuilder jb = new JarBuilder( new LogConsole(), "AcceptData.jar" );
		jb.addDirectory( ".bin" );
		jb.addDirectory( "../../lib/libDenomCommon/.bin" );
		jb.addDirectory( "../../lib/libDenomCrypt/.bin" );
		jb.addDirectory( "../../lib/libDenomD5/.bin" );
		jb.addManifest( relay.AcceptData.class );
		jb.close();

		ProGuard pg = new ProGuard( log, "../../tools/proguard.jar" );
		pg.obfuscateJar( "AcceptData.jar", ProGuard.paramsApp(), null );
	}
}
