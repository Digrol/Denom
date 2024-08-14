// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.build;

import java.io.*;
import java.nio.file.*;
import java.util.zip.*;

import org.denom.Binary;
import org.denom.log.*;

import static org.denom.Ex.*;

/**
 * Building obfuscated WARs.
 */
public class WarBuilder
{
	private final String proguardPath;
	private final ILog log;

	// -----------------------------------------------------------------------------------------------------------------
	public WarBuilder( ILog log, String proguardPath )
	{
		this.log = log;
		this.proguardPath = proguardPath;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Building WAR-file with obfuscation of all classes, except servlet-classes.
	 * @param warPath - path to output WAR-file.
	 * @param webContentPath - Directory with WEB-pages, pictures, etc., usually './WebContent'.
	 *   Must contain WEB-INF/web.xml and META-INF/MANIFEST.MF.
	 * @param inClassPaths - Directories and JAR-files with project classes. Can be 'null'.
	 * @param externalJars - external JARs, will be copied to 'WEB-INF/lib'.
	 */
	public void buildWar( String warPath, String webContentPath, String proguardParams, String[] inClassPaths, String[] externalJars )
	{
		log.writeln( "Creating WAR '" + warPath + "'..." );

		// Build 'jarServlet' - JAR-file with obfuscated input class-files. External JARs are not included.
		String jarServlet = warPath.replace( ".war", ".jar" );
		if( inClassPaths != null )
		{
			JarBuilder jb = new JarBuilder( log, jarServlet );
			for( String classPath : inClassPaths )
			{
				if( Files.isDirectory( Paths.get( classPath ) ) )
					jb.addDirectory( classPath );
				else
					jb.addZip( classPath );
			}
			jb.close();

			// Obfuscating JAR as servlet.
			new ProGuard( log, proguardPath ).obfuscateJar( jarServlet, proguardParams, externalJars );
		}


		try( ZipOutputStream war = new ZipOutputStream( new FileOutputStream( warPath ) ) )
		{
			// Add directory 'WebContent' to WAR
			JarBuilder.addDirToZip( war, webContentPath, null );

			// Add 'jarServlet' to 'WEB-INF/lib/' in WAR
			if( inClassPaths != null )
			{
				war.putNextEntry( new ZipEntry( "WEB-INF/lib/" + Paths.get( jarServlet ).getFileName() ) );
				war.write( new Binary().loadFromFile( jarServlet ).getBytes() );
				Files.deleteIfExists( Paths.get( jarServlet ) );
			}

			// Add all 'externalJars' to 'WEB-INF/lib/'
			if( externalJars != null )
			{
				for( String extJar : externalJars )
				{
					Path p = Paths.get( extJar );
					war.putNextEntry( new ZipEntry( "WEB-INF/lib/" + p.getFileName() ) );
					war.write( new Binary().loadFromFile( p.toString() ).getBytes() );
				}
			}
		}
		catch( Throwable ex )
		{
			THROW( ex );
		}

		log.writeln( "WAR created" );
	}

}
