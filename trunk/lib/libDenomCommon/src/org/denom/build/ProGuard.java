// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.build;

import org.denom.Sys;
import org.denom.log.*;

import static org.denom.Ex.*;

/**
 * Obfuscate JAR-files and WAR-files with ProGuard tool.
 */
public class ProGuard
{
	private final String proguardPath;
	private final String javaRuntimeJarPath;
	private final ILog log;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param javaRuntimeJarPath - path to "<JAVA_HOME>/jre/lib/rt.jar".
	 * @param proguardPath - path to "proguard.jar".
	 */
	public ProGuard( ILog log, String proguardJarPath, String javaRuntimeJarPath )
	{
		this.proguardPath = proguardJarPath;
		this.log = log;
		this.javaRuntimeJarPath = javaRuntimeJarPath;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Environment variable "JAVA_HOME" must be set.
	 * @param proguardJarPath - path to "proguard.jar".
	 */
	public ProGuard( ILog log, String proguardJarPath )
	{
		this.proguardPath = proguardJarPath;
		this.log = log;

		javaRuntimeJarPath = System.getenv("JAVA_HOME") + "/jre/lib/rt.jar";
		Sys.checkFileExist( javaRuntimeJarPath );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Obfuscate JAR-file.
	 * @param jarPath - path to JAR-file to process.
	 * @param externalJars - List of jar-files to check external links from classes; can be null.
	 */
	public void obfuscateJar( String jarPath, String proguardParams, String[] externalJars )
	{
		StringBuilder sb = new StringBuilder( 2048 );

		sb.append( " -injars " + jarPath );
		sb.append( " -outjars temp.jar" );
		sb.append( " -libraryjars " + javaRuntimeJarPath );

		if( externalJars != null )
		{
			for( String libJar : externalJars )
			{
				sb.append( ';' );
				sb.append( libJar );
			}
		}

		sb.append( proguardParams );

		run( sb.toString() );
		Sys.renameFile( "temp.jar", jarPath );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Run ProGuard as java-program.
	 * @param params - All params for Proguard. See ProGuard manual.
	 */
	public void run( String params )
	{
		StringBuilder cmdLine = new StringBuilder( 2048 );
		cmdLine.append( "java -jar " + proguardPath );
		cmdLine.append( " " );
		cmdLine.append( params );

		log.writeln( "Start ProGuard..." );
		int res = Sys.execAndWait( cmdLine.toString(), log );
		MUST( res == 0, "ProGuard failed" );
		log.writeln( "OK" );
	}

	// =================================================================================================================
	/**
	 * Obfuscation parameters for desktop applications.
	 * Don't touch only public-classes with 'main' method.
	 */
	public static String paramsApp()
	{
		StringBuilder sb = new StringBuilder( 1024 );
		sb.append( " -keepattributes Exceptions,InnerClasses,Signature,*Annotation*,EnclosingMethod" );
		sb.append( " -keepclasseswithmembernames,includedescriptorclasses \"class * {native <methods>;}\"" );
		sb.append( " -keepclassmembers \"class * extends java.lang.Enum { <fields>; public static **[] values(); public static ** valueOf(java.lang.String); }\"" );
		sb.append( " -keepclasseswithmembers \"public class * {public static void main(java.lang.String[]);}\"" );
		sb.append( " -repackageclasses" );
		sb.append( " -allowaccessmodification" );
		sb.append( " -forceprocessing" );
		sb.append( " -dontnote org.denom.ecj.JavaCompilerECJ" );

		return sb.toString();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Obfuscation parameters for HTTP-servlets.
	 * Don't touch only public-classes implementing servlet API.
	 * Environment variable "TOMCAT" must be set for jar "<TOMCAT>/lib/servlet-api.jar".
	 */
	public static String paramsServlet()
	{
		StringBuilder sb = new StringBuilder( 1024 );
		sb.append( " -keepattributes Exceptions,InnerClasses,Signature,*Annotation*,EnclosingMethod" );
		sb.append( " -keepclasseswithmembernames,includedescriptorclasses \"class * {native <methods>;}\"" );
		sb.append( " -keepclassmembers \"class * extends java.lang.Enum { <fields>; public static **[] values(); public static ** valueOf(java.lang.String); }\"" );
		sb.append( " -keep,includedescriptorclasses \"public class * extends    javax.servlet.http.HttpServlet\"" );
		sb.append( " -keep,includedescriptorclasses \"public class * implements javax.servlet.Filter\"" );
		sb.append( " -repackageclasses" );
		sb.append( " -allowaccessmodification" );
		sb.append( " -forceprocessing" );
		sb.append( " -dontnote org.denom.ecj.JavaCompilerECJ" );

		String servletApiJar = System.getenv("TOMCAT") + "/lib/servlet-api.jar";
		Sys.checkFileExist( servletApiJar );
		sb.append( " -libraryjars " + servletApiJar );

		return sb.toString();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Obfuscation parameters for libraries and applications, that use ECJ.
	 * All public classes is not changed.
	 */
	public static String paramsLib()
	{
		StringBuilder sb = new StringBuilder( 1024 );
		sb.append( " -keepattributes Exceptions,InnerClasses,Signature,*Annotation*,EnclosingMethod" );
		sb.append( " -keepclasseswithmembernames,includedescriptorclasses \"class * {native <methods>;}\"" );
		sb.append( " -keep,includedescriptorclasses \"public class * {public protected *;}\"" );
		sb.append( " -dontoptimize" );
		sb.append( " -forceprocessing" );
		sb.append( " -dontnote org.denom.ecj.JavaCompilerECJ" );
		return sb.toString();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * ProGuard only processes Input and builds Output..
	 */
	public static String paramsNop()
	{
		StringBuilder sb = new StringBuilder( 100 );
		sb.append( " -dontshrink" );
		sb.append( " -dontoptimize" );
		sb.append( " -dontobfuscate" );
		sb.append( " -dontpreverify" );
		sb.append( " -forceprocessing" );
		return sb.toString();
	}

}
