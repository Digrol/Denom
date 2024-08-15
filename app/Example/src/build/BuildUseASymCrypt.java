package build;

import org.denom.build.*;
import org.denom.log.*;

class BuildUseASymCrypt
{
	public static void main( String[] args )
	{
		String jarName = "UseASymCrypt.jar";
		String ROOT = "../..";

		ILog log = new LogConsole();
		JarBuilder jb = new JarBuilder( new LogConsole(), jarName );
		jb.addDirectory( ".bin" );
		jb.addZip( ROOT + "/builds/libs/org.denom.common-2024.08.15.jar" );
		jb.addZip( ROOT + "/builds/libs/org.denom.crypt-2024.08.15.jar" );
		jb.addManifest( example.UseASymCrypt.class );
		jb.close();

		ProGuard pg = new ProGuard( log, ROOT + "/tools/proguard.jar" );
		pg.obfuscateJar( jarName, ProGuard.paramsApp(), null );
	}
}
