// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom;

import java.util.Random;

/**
 * Class for returning ints from method. Example:
 * Int int1 = new Int();
 * Int int2 = new Int();
 * bool f( Int int1, Int int2 );
 */
public class Int
{
	public int val;

	public Int() {}

	public Int( int value )
	{
		this.val = value;
	}


	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return true, if 0 <= num <= 0xFF.
	 */
	public static boolean isU8( int num )
	{
		return (num & 0xFFFFFF00) == 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return true, if 0 <= num <= 0xFFFF.
	 */
	public static boolean isU16( int num )
	{
		return (num & 0xFFFF0000) == 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return true, if 0 <= num <= 0xFFFFFF.
	 */
	public static boolean isU24( int num )
	{
		return (num & 0xFF000000) == 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return true, if 0 <= num <= 0xFFFFFFFF.
	 */
	public static boolean isU32( long num )
	{
		return (num & 0xFFFFFFFF00000000L) == 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Глобальный генератор случайных чисел.
	 */
	private static Random rand = new Random( System.nanoTime() );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сгенерировать случайное число в заданном диапазоне: [min, max]
	 */
	public static int RangedRand( int min, int max )
	{
		Ex.MUST( min < max, "Wrong range" );
		return rand.nextInt( max - min + 1 ) + min;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static long RangedRand( long min, long max )
	{
		Ex.MUST( (min < max) && ((max - min) > 0) && ((max - min) < Long.MAX_VALUE), "Wrong range" );
		long l = rand.nextLong() % (max - min + 1);
		if( l < 0 )
		{
			l = -l;
		}
		l = l + min;
		return l;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Округлить {@code number} вверх до ближайшего значения, кратного {@code modulo}.
	 * @param number Округляемое число
	 * @param modulo Кратность
	 * @return Результат округления
	 */
	public static int roundUp( int number, int modulo )
	{
		return ((number + modulo - 1) / modulo) * modulo;
	}

}
