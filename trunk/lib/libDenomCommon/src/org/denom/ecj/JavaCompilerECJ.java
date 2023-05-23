// Denom.org
// Author:  Alexey Sovkov,  as.sovkov@gmail.com

package org.denom.ecj;

import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.nio.charset.Charset;
import java.util.*;
import javax.tools.*;
import javax.tools.JavaCompiler.*;

/**
 * Компиляция Java-файлов в рантайме, c помощью компилятора ECJ.
 * Пример компиляции файла:
 *     Class<MyInterface> clazz = (Class<MyInterface>)new JavaCompilerECJ().compile( "MyClass.java" );
 * Пример создания экземпляра:
 *     MyInterface instance = (MyInterface)new JavaCompilerECJ().getInstance( "MyClass.java" );
 */
public class JavaCompilerECJ
{
	private static final String JAVA_COMPLIANCE = "1.8";

	JavaCompiler javac;
	private MyClassLoader classLoader = new MyClassLoader();

	private Map<String, MemoryByteCode> compiledClasses = new HashMap<String, MemoryByteCode>();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Check invariant.
	 * @param expression - If expression == false, then throw RuntimeException with message.
	 */
	private static void MUST( boolean expression, String message )
	{
		if( !expression )
		{
			throw new RuntimeException( message );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public JavaCompilerECJ()
	{
		try
		{
			javac = (JavaCompiler)Class.forName( "org.eclipse.jdt.internal.compiler.tool.EclipseCompiler" ).getDeclaredConstructor().newInstance();
		}
		catch( Throwable ex )
		{
			throw new RuntimeException( "ECJ compiler not found" );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Загрузить из файла данные как массив байт.
	 */
	private static byte[] loadFile( String fileName )
	{
		try
		(
			FileInputStream fis = new FileInputStream( fileName );
			BufferedInputStream bufInputStream = new BufferedInputStream( fis );
		)
		{
			int size = bufInputStream.available();
			MUST( size < Integer.MAX_VALUE, "Размер файла должен быть меньше максимального размера int" );

			byte[] buf = new byte[ size ];
			bufInputStream.read( buf );
			return buf;
		}
		catch( IOException e )
		{
			throw new RuntimeException( e.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Скомпилировать Java-класс.
	 * @param srcFilename - имя файла-исходника на Java.
	 * @return объект Class с информацией о скомпилированном классе.
	 */
	public Class<?> compile( String srcFilename )
	{
		StandardJavaFileManager sjfm = javac.getStandardFileManager( null, null, null );
		MyJavaFileManager fileManager = new MyJavaFileManager( sjfm );

		List<String> options = new ArrayList<String>();
		options.add( "-" + JAVA_COMPLIANCE );
		options.add( "-classpath" );
		options.add( System.getProperty( "java.class.path" ) );

		byte[] buf = loadFile( srcFilename );
		String sourceCode = new String( buf, 0, buf.length, Charset.forName( "UTF-8" ) );
		
		MemorySource compilationUnit = new MemorySource( srcFilename.replace( "\\", "/" ), sourceCode );
		StringWriter out = new StringWriter();
		
		CompilationTask compile = javac.getTask( out, fileManager, null, options, null, Arrays.asList( compilationUnit ) );
		MUST( compile.call(), "Ecj compiler error: \n" + out.toString() );

		Class<?> compiledClass = null;

		for( Map.Entry<String, MemoryByteCode> entry : compiledClasses.entrySet() )
		{
			Class<?> aClass = classLoader.loadClass( entry.getKey(), entry.getValue() );

			if( Modifier.isPublic( aClass.getModifiers() ) )
			{
				MUST( compiledClass == null, "More than one public class" );
				compiledClass = aClass;
			}
		}

		compiledClasses.clear();

		MUST( compiledClass != null, "No public class found" );
		return compiledClass;
	}

	// ---------------------------------------------------------------------------------------------------------------------
	public Object getInstance( String srcFilename )
	{
		try
		{
			return compile( srcFilename ).getDeclaredConstructor().newInstance();
		}
		catch( Exception ex )
		{
			throw new RuntimeException( ex.toString() );
		}
	}

	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	private class MyClassLoader extends ClassLoader
	{
		Class<?> loadClass( String name, MemoryByteCode mbc )
		{
			return super.defineClass( name, mbc.getBytes(), 0, mbc.getBytes().length );
		}
	}

	// ---------------------------------------------------------------------------------------------------------------------
	private class MemorySource extends SimpleJavaFileObject
	{
		private String src;

		public MemorySource( String name, String src )
		{
			super( new File( name ).toURI(), Kind.SOURCE );
			this.src = src;
		}
		
		@Override
		public CharSequence getCharContent( boolean ignoreEncodingErrors )
		{
			return src;
		}

		@Override
		public OutputStream openOutputStream()
		{
			throw new IllegalStateException();
		}
		
		@Override
		public InputStream openInputStream()
		{
			return new ByteArrayInputStream( src.getBytes() );
		}
	}

	// ---------------------------------------------------------------------------------------------------------------------
	private class MyJavaFileManager extends ForwardingJavaFileManager<JavaFileManager>
	{
		MyJavaFileManager( StandardJavaFileManager sjfm )
		{
			super( sjfm );
		}

		// -----------------------------------------------------------------------------------------------------------------
		@Override
		public JavaFileObject getJavaFileForOutput( Location location, String name, JavaFileObject.Kind kind, 
			FileObject sibling ) throws IOException
		{
			MemoryByteCode mbc = new MemoryByteCode( name );
			name = name.replace( "/", "." );
			compiledClasses.put( name, mbc );
			return mbc;
		}

		@Override
		public ClassLoader getClassLoader( Location location )
		{
			return classLoader;
		}
	}

	// ---------------------------------------------------------------------------------------------------------------------
	private class MemoryByteCode extends SimpleJavaFileObject
	{
		private ByteArrayOutputStream baos;
		
		public MemoryByteCode( String name )
		{
			super( URI.create("byte:///" + name + ".class"), Kind.CLASS );
		}
		
		@Override
		public CharSequence getCharContent( boolean ignoreEncodingErrors )
		{
			throw new IllegalStateException();
		}
		
		@Override
		public OutputStream openOutputStream()
		{
			baos = new ByteArrayOutputStream();
			return baos;
		}
		
		@Override
		public InputStream openInputStream()
		{
			throw new IllegalStateException();
		}
		
		public byte[] getBytes()
		{
			return baos.toByteArray();
		}
	}

}
