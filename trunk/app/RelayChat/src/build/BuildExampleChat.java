package build;

import org.denom.build.*;
import org.denom.log.*;

class BuildExampleChat
{
	public static void main( String[] args )
	{
		ILog log = new LogConsole();
		JarBuilder jb = new JarBuilder( new LogConsole(), "RelayChat.jar" );
		jb.addDirectory( ".bin" );
		jb.addDirectory( "../../lib/libDenomCommon/.bin" );
		jb.addDirectory( "../../lib/libDenomCrypt/.bin" );
		jb.addDirectory( "../../lib/libDenomD5/.bin" );

		jb.addManifest( relaychat.ExampleChatMain.class );
		jb.close();

		ProGuard pg = new ProGuard( log, "../../tools/proguard.jar" );
		pg.obfuscateJar( "RelayChat.jar", ProGuard.paramsApp(), null );
	}
}
