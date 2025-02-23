package build;

import org.denom.build.*;
import org.denom.log.LogConsole;

class TerminalKernel8
{
	public static void main( String[] args )
	{
		LogConsole log = new LogConsole();

		JarBuilder jb = new JarBuilder( log, "TerminalKernel8.jar" );

		jb.addManifest( org.denom.terminal.kernel8.TerminalKernel8GUI.class );
		jb.addDirectory( "../../lib/libDenomCommon/.bin" );
		jb.addDirectory( "../../lib/libDenomCrypt/.bin" );
		jb.addDirectory( "../../lib/libDenomSmartCard/.bin" );
		jb.addDirectory( ".bin" );
		jb.exclude( "build" );
		jb.close();

		String s = "";
		s += " -keepattributes Exceptions,InnerClasses,Signature,*Annotation*,EnclosingMethod";
		s += " -keepnames \"class *\"";
		s += " -keepclasseswithmembernames,includedescriptorclasses \"class * {native <methods>;}\"";
		s += " -keepclassmembers \"class * extends java.lang.Enum { <fields>; public static **[] values(); public static ** valueOf(java.lang.String); }\"";
		s += " -keepclasseswithmembers \"public class * {public static void main(java.lang.String[]);}\"";
		s += " -forceprocessing";
		s += " -dontnote org.denom.ecj.JavaCompilerECJ";
		s += " -dontnote org.denom.format.BinParser";

		ProGuard pg = new ProGuard( log, "../../tools/proguard.jar" );
		pg.obfuscateJar( "TerminalKernel8.jar", s, null );
	}
}
