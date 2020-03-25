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
		jb.addDirectory( "../../lib/libDenomRelay/.bin" );
		//jb.addZip( "../../../libs/org.denom.crypt-2020.02.16.jar" );
		jb.addManifest( relaychat.ExampleRelayChat.class );
		jb.close();

		ProGuard pg = new ProGuard( log, "../../tools/proguard.jar" );
		pg.obfuscateJar( "RelayChat.jar", ProGuard.paramsApp(), null );
	}
}
