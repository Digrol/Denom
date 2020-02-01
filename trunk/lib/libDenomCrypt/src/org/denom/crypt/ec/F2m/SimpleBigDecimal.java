package org.denom.crypt.ec.F2m;

import java.math.BigInteger;

import static org.denom.Ex.MUST;

/**
 * Simple version of a big decimal. A <code>SimpleBigDecimal</code> is
 * basically a {@link java.math.BigInteger BigInteger} with a few digits on the right of the decimal
 * point. The number of (binary) digits on the right of the decimal point is called the
 * <code>scale</code> of the <code>SimpleBigDecimal</code>. Unlike in {@link java.math.BigDecimal
 * BigDecimal}, the scale is not adjusted automatically, but must be set manually. All
 * <code>SimpleBigDecimal</code>s taking part in the same arithmetic operation must have equal
 * scale. The result of a multiplication of two <code>SimpleBigDecimal</code>s returns a
 * <code>SimpleBigDecimal</code> with double scale.
 */
class SimpleBigDecimal
{
	private final BigInteger bigInt;
	final int scale;

	SimpleBigDecimal( BigInteger bigInt, int scale )
	{
		this.bigInt = bigInt;
		this.scale = scale;
	}

	SimpleBigDecimal adjustScale( int newScale )
	{
		MUST( newScale >= 0, "scale may not be negative" );
		if( newScale == scale )
		{
			return this;
		}
		return new SimpleBigDecimal( bigInt.shiftLeft( newScale - scale ), newScale );
	}

	SimpleBigDecimal add( SimpleBigDecimal b )
	{
		MUST( scale == b.scale );
		return new SimpleBigDecimal( bigInt.add( b.bigInt ), scale );
	}

	SimpleBigDecimal negate()
	{
		return new SimpleBigDecimal( bigInt.negate(), scale );
	}

	SimpleBigDecimal subtract( SimpleBigDecimal b )
	{
		return add( b.negate() );
	}

	SimpleBigDecimal subtract( BigInteger b )
	{
		return new SimpleBigDecimal( bigInt.subtract( b.shiftLeft( scale ) ), scale );
	}

	int compareTo( BigInteger val )
	{
		return bigInt.compareTo( val.shiftLeft( scale ) );
	}

	BigInteger floor()
	{
		return bigInt.shiftRight( scale );
	}

	BigInteger round()
	{
		SimpleBigDecimal oneHalf = new SimpleBigDecimal( BigInteger.ONE, 1 );
		return add( oneHalf.adjustScale( scale ) ).floor();
	}

	public boolean equals( Object o )
	{
		if( this == o )
		{
			return true;
		}

		if( !(o instanceof SimpleBigDecimal) )
		{
			return false;
		}

		SimpleBigDecimal other = (SimpleBigDecimal)o;
		return ((bigInt.equals( other.bigInt )) && (scale == other.scale));
	}

}
