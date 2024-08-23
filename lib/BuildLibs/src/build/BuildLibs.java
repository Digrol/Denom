package build;

import org.denom.build.*;
import org.denom.log.LogConsole;

/**
 * Build JAR-files with Denom libs for Java desktop and Android platforms.
 */
class BuildLibs
{
	static String BUILD_DATE = "2024.08.20";

	static String ROOT = "../..";

	static LogConsole log = new LogConsole();


	static String[] excludeAndroid = {
			"/build",
			"/ecj",
			"/swing",
			"/testrunner",
			"LogColoredConsoleWindow.java", "LogColoredConsoleWindow.class",
			"LogColoredTextPane.java",      "LogColoredTextPane.class",

			"CardReaderPCSC.java",          "CardReaderPCSC.class",
			"CardReaderPCSCNative.java",    "CardReaderPCSCNative.class",
			"ReaderFactory.java",           "ReaderFactory.class",
			"CardScript.java",              "CardScript.class",
			"PanelSelectReader.java",       "PanelSelectReader.class",
			"SecurityModuleSAM.java",       "SecurityModuleSAM.class"
	};

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args ) throws Exception
	{
		buildLib( "org.denom.common",         "libDenomCommon" );
		buildLib( "org.denom.crypt",          "libDenomCrypt" );
		buildLib( "org.denom.smartcard",      "libDenomSmartcard" );
		buildLib( "org.denom.smartcard-full", "libDenomSmartcard", "libDenomCrypt", "libDenomCommon" );

		buildLibAndroid( "org.denom.common", excludeAndroid, "libDenomCommon" );
		buildLibAndroid( "org.denom.smartcard-full", excludeAndroid, "libDenomSmartcard", "libDenomCrypt", "libDenomCommon" );
	}

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
	private static void buildLibAndroid( String jarPrefix, String[] excludeAndroid, String... projectNames )
	{
		String jarName = ROOT + "/builds/libsAndroid/" + jarPrefix + "-android-" + BUILD_DATE + ".jar";

		// Jar
		JarBuilder jb = new JarBuilder( log, jarName );
		jb.exclude( excludeAndroid );
		for( String projectName : projectNames )
			jb.addDirectory( ROOT + "/lib/" + projectName + "/.bin" );
		jb.close();

		// Sources
		jb = new JarBuilder( log, jarName.replace( ".jar", "-sources.jar" ) );
		jb.exclude( excludeAndroid );
		for( String projectName : projectNames )
			jb.addDirectory( ROOT + "/lib/" + projectName + "/src" );
		jb.close();
	}

}
