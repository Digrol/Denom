package build;

import org.denom.build.*;
import org.denom.log.LogConsole;

/**
 * Build JAR-files with Denom libs for Java desktop platform.
 */
class BuildLibs
{
	static String BUILD_DATE = "2020.02.09";

	static String TRUNK_PATH = "../..";
	static String LIBS_PATH = "../../../libs";

	// -----------------------------------------------------------------------------------------------------------------
	private static void buildLib( String projectName, String jarName )
	{
		LogConsole log = new LogConsole();

		JarBuilder jb = new JarBuilder( log, LIBS_PATH + "/" + jarName + "-" + BUILD_DATE + ".jar" );
		jb.addDirectory( TRUNK_PATH + "/lib/" + projectName + "/.bin" );
		jb.close();
		
		jb = new JarBuilder( log, LIBS_PATH + "/" + jarName + "-" + BUILD_DATE + "-sources.jar" );
		jb.addDirectory( TRUNK_PATH + "/lib/" + projectName + "/src" );
		jb.close();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args ) throws Exception
	{
		buildLib( "libDenomCommon", "org.denom.common" );
		buildLib( "libDenomCrypt", "org.denom.crypt" );
		//buildLib( "libDenomRelay", "org.denom.relay" );
	}

}
