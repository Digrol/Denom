package build;

import org.denom.build.*;
import org.denom.log.LogConsole;

/**
 * Build JAR-files with Denom libs for Java desktop and Android platforms.
 */
class BuildLibs
{
	static String BUILD_DATE = "2024.08.15";

	static String ROOT = "../..";

	static LogConsole log = new LogConsole();

	// -----------------------------------------------------------------------------------------------------------------
	static String[] excludeAndroid = {
			"/build",
			"/ecj",
			"/swing",
			"/testrunner",
			"LICENSE.txt",
			"LogColoredConsoleWindow.java", "LogColoredConsoleWindow.class",
			"LogColoredTextPane.java",      "LogColoredTextPane.class"
	};

	// -----------------------------------------------------------------------------------------------------------------
	private static void buildLib( String jarPrefix, String... projectNames )
	{
		String jarName = ROOT + "/builds/libs/" + jarPrefix + "-" + BUILD_DATE + ".jar";

		// Jar
		JarBuilder jb = new JarBuilder( log, jarName );
		jb.exclude( "LICENSE.txt" );
		for( String projectName : projectNames )
			jb.addDirectory( ROOT + "/lib/" + projectName + "/.bin" );
		jb.close();

		// Sources
		jb = new JarBuilder( log, jarName.replace( ".jar", "-sources.jar" ) );
		jb.exclude( "LICENSE.txt" );
		for( String projectName : projectNames )
			jb.addDirectory( ROOT + "/lib/" + projectName + "/src" );
		jb.close();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void buildLibAndroid( String jarPrefix, String projectName )
	{
		String libPath = ROOT + "/lib/" + projectName;
		String jarName = ROOT + "/builds/libsAndroid/" + jarPrefix + "-android-" + BUILD_DATE + ".jar";

		// Jar
		JarBuilder jb = new JarBuilder( log, jarName );
		jb.exclude( excludeAndroid );
		jb.addDirectory( libPath + "/.bin" );
		jb.close();

		// Sources
		jb = new JarBuilder( log, jarName.replace( ".jar", "-sources.jar" ) );
		jb.exclude( excludeAndroid );
		jb.addDirectory( libPath + "/src" );
		jb.close();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args ) throws Exception
	{
		buildLib( "org.denom.common",         "libDenomCommon" );
		buildLib( "org.denom.crypt",          "libDenomCrypt" );
		buildLib( "org.denom.smartcard",      "libDenomSmartcard" );
		buildLib( "org.denom.smartcard-full", "libDenomSmartcard", "libDenomCrypt", "libDenomCommon" );

		buildLibAndroid( "org.denom.common", "libDenomCommon" );
	}

}
