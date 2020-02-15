package build;

import org.denom.build.*;
import org.denom.log.LogConsole;

/**
 * Build JAR-files with Denom libs for Android platform.
 */
class BuildLibsAndroid
{
	static String BUILD_DATE = "2020.02.16";

	static String TRUNK_PATH = "../..";
	static String LIBS_PATH = "../../../libsAndroid";

	static String[] exclude = {
			"/build",
			"/ecj",
			"/swing",
			"/testrunner",
			"LogColoredConsoleWindow.java", "LogColoredConsoleWindow.class",
			"LogColoredTextPane.java",      "LogColoredTextPane.class"
	};

	// -----------------------------------------------------------------------------------------------------------------
	static void buildLib( String projectName, String jarName )
	{
		LogConsole log = new LogConsole();

		JarBuilder jb = new JarBuilder( log, LIBS_PATH + "/" + jarName + "-" + BUILD_DATE + ".jar" );
		jb.exclude( exclude );
		jb.addDirectory( TRUNK_PATH + "/lib/" + projectName + "/.bin" );
		jb.close();

		jb = new JarBuilder( log, LIBS_PATH + "/" + jarName + "-" + BUILD_DATE + "-sources.jar" );
		jb.exclude( exclude );
		jb.addDirectory( TRUNK_PATH + "/lib/" + projectName + "/src" );
		jb.close();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args ) throws Exception
	{
		buildLib( "libDenomCommon", "org.denom.common-android" );
		buildLib( "libDenomCrypt", "org.denom.crypt-android" );
		//buildLib( "libDenomRelay", "org.denom.relay-android" );
	}

}
