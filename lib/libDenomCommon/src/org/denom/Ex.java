// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom;

/**
 * One exception class for almost any case.
 */
public class Ex extends RuntimeException
{
	private static String ln = "\n";

	static
	{
		try
		{
			ln = System.getProperty("line.separator");
		}
		catch( Throwable ex ) {}
	}

	/**
	 * Error code.
	 */
	public int code;

	/**
	 * Error location.
	 */
	public String place = "";

	public Ex()
	{
		super( "" );
	}

	/**
	 * @param errorCode - Error code.
	 */
	public Ex( int errorCode )
	{
		super( "" );
		this.code = errorCode;
	}

	/**
	 * @param errorCode - Error code.
	 * @param message - Error description.
	 */
	public Ex( int errorCode, String message )
	{
		super( message );
		this.code = errorCode;
	}

	/**
	 * @param message - Error description.
	 */
	public Ex( String message )
	{
		super( message );
	}

	/**
	 * @param message - Error description.
	 * @param cause - catched Exception.
	 */
	public Ex( String message, Throwable cause )
	{
		super( message, cause );
	}

	public Ex( int errorCode, String message, Throwable cause )
	{
		super( message, cause );
		this.code = errorCode;
	}

	/**
	 * @param cause - caught Exception.
	 */
	public Ex( Throwable cause )
	{
		super( cause );
	}

	/**
	 * @param message - Error description.
	 * @param place - location of error.
	 */
	public Ex( String message, String place )
	{
		super( message );
		this.place = place;
	}

	@Override
	public String toString()
	{
		String msg = super.toString();
		if( code != 0 )
		{
			msg += (ln + "Error code: "+ code);
		}
		if( !place.isEmpty() )
		{
			msg += (ln + "Place: "+ place);
		}
		return msg;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * throw Exception {@link org.denom.Ex} with message and/or errorCode.
	 * с заданным сообщением и/или кодом ошибки.
	 */
	public static void THROW( String message )
	{
		throw new Ex( message );
	}

	public static void THROW( int errorCode )
	{
		throw new Ex( errorCode );
	}

	public static void THROW( int errorCode, String message )
	{
		throw new Ex( errorCode, message );
	}

	public static void THROW( Throwable ex )
	{
		throw new Ex( ex );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Check invariant.
	 * @param expression - If expression == false, then throw exception Ex
	 * with message and/or errorCode.
	 */
	public static void MUST( boolean expression, String message )
	{
		if( !expression )
		{
			throw new Ex( message );
		}
	}

	public static void MUST( boolean expression )
	{
		if( !expression )
		{
			throw new Ex( "No message" );
		}
	}

	public static void MUST( boolean expression, int errorCode )
	{
		if( !expression )
		{
			throw new Ex( errorCode );
		}
	}

	public static void MUST( boolean expression, int errorCode, String message )
	{
		if( !expression )
		{
			throw new Ex( errorCode, message );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static String getStackStr( Throwable ex )
	{
		StringBuilder str = new StringBuilder( 1000 );

		StackTraceElement[] stack = ex.getStackTrace();
		for( int i = 0; i < stack.length; ++i )
		{
			if( stack[i].getMethodName().equals( "MUST" ) || stack[i].getMethodName().equals( "THROW" ) )
			{
				continue;
			}
			str.append( ln );
			str.append( "    " );
			str.append( stack[i].toString() );
		}
		return str.toString();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Get description of error as String (with call stack).
	 * MUST and THROW is not written in stack.
	 */
	public static String getErrorDescription( Throwable ex )
	{
		StringBuilder str = new StringBuilder( 1000 );
		str.append( ex.toString() );

		str.append( ln );
		str.append( "Stack:" );
		str.append( getStackStr( ex ) );
		return str.toString();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Information about the class that called the methods of the 'className' class.
	 */
	public static String getCallerPlace( String className )
	{
		StackTraceElement[] stack = new Throwable().getStackTrace();
		if( stack.length < 2 )
		{
			return "";
		}

		int i = 0;
		for( ; i < stack.length; ++i )
		{
			StackTraceElement elem = stack[ i ];
			if( elem.getClassName().equals( className ) )
			{
				break; // found methods of 'className'
			}
		}

		for( ; i < stack.length; ++i )
		{
			StackTraceElement elem = stack[ i ];
			if( !elem.getClassName().equals( className ) )
			{
				return elem.toString();
			}
		}
		return "";
	}

	private static final long serialVersionUID = 1L;
}
