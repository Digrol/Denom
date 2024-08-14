package build;

import org.denom.build.*;
import org.denom.log.*;

class BuildUseASymCrypt
{
	public static void main( String[] args )
	{
		ILog log = new LogConsole();
		JarBuilder jb = new JarBuilder( new LogConsole(), "UseASymCrypt.jar" );
		jb.addDirectory( ".bin" );
		jb.addZip( "../../../libs/org.denom.common-2020.02.07.jar" );
		jb.addZip( "../../../libs/org.denom.crypt-2020.02.07.jar" );
		jb.addManifest( example.UseASymCrypt.class );
		jb.close();

		ProGuard pg = new ProGuard( log, "../../tools/proguard.jar" );
		pg.obfuscateJar( "UseASymCrypt.jar", ProGuard.paramsApp(), null );
	}
}
