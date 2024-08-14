package build;

import org.denom.build.*;
import org.denom.log.LogConsole;

/**
 * Build JAR-files with Denom libs for Java desktop and Android platforms.
 */
class BuildLibs
{
	static String BUILD_DATE = "2023.05.23";

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
	private static void buildLib( String projectName, String jarPrefix )
	{
		String libPath = ROOT + "/lib/" + projectName;
		String jarName = ROOT + "/builds/libs/" + jarPrefix + "-" + BUILD_DATE + ".jar";

		// Jar
		JarBuilder jb = new JarBuilder( log, jarName );
		jb.exclude( "LICENSE.txt" );
		jb.addDirectory( libPath + "/.bin" );
		jb.close();

		// Sources
		jb = new JarBuilder( log, jarName.replace( ".jar", "-sources.jar" ) );
		jb.exclude( "LICENSE.txt" );
		jb.addDirectory( libPath + "/src" );
		jb.close();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static void buildLibAndroid( String projectName, String jarPrefix )
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
		buildLib( "libDenomCommon", "org.denom.common" );
		buildLibAndroid( "libDenomCommon", "org.denom.common" );

		buildLib( "libDenomCrypt", "org.denom.crypt" );

		buildLib( "libDenomSmartcard", "org.denom.smartcard" );
}

}
