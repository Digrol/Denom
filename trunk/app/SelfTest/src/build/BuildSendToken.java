package build;

import org.denom.build.*;
import org.denom.log.*;

class BuildSendToken
{
	public static void main( String[] args )
	{
		ILog log = new LogConsole();
		JarBuilder jb = new JarBuilder( new LogConsole(), "SendD5Token.jar" );
		jb.addDirectory( ".bin" );
		jb.addZip( "../../../libs/org.denom.common-2020.02.16.jar" );
		jb.addZip( "../../../libs/org.denom.crypt-2020.02.16.jar" );
		jb.addManifest( sendtoken.SendExecuteToken.class );
		jb.close();

		ProGuard pg = new ProGuard( log, "../../tools/proguard.jar" );
		pg.obfuscateJar( "SendD5Token.jar", ProGuard.paramsApp(), null );
	}
}
