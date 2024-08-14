// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import java.io.IOException;
import java.io.RandomAccessFile;
import org.denom.Binary;

import static org.denom.Ex.*;

/**
 * Abstract cryptographic hash function.
 * Processes binary data and produces 'hash' (another byte array).
 * 1. Calculating hash in one step:
 *      Binary hash = new IHash().calc( data );
 * 2. Calculating hash by parts, using 'reset', 'process', 'getHash':
 *      IHash alg = new IHash();
 *      alg.process( part1 );
 *      alg.process( partN );
 *      Binary hash = alg.getHash();
 */
public abstract class IHash implements Cloneable
{
	// -----------------------------------------------------------------------------------------------------------------
	final int blockSize;
	Binary tail;
	long processedBytes = 0;

	// -----------------------------------------------------------------------------------------------------------------
	protected IHash( int blockSize )
	{
		this.blockSize = blockSize;
		this.tail = new Binary().reserve( blockSize );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Size of producing hash in bytes.
	 */
	public abstract int size();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Hashing algorithm name.
	 */
	public abstract String name();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Calculate hash of data.
	 */
	public final Binary calc( final Binary data )
	{
		return calc( data, 0, data.size() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Calculate hash of data.
	 */
	public final Binary calc( final Binary data, int offset, int len )
	{
		reset();
		process( data, offset, len );
		return getHash();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Resets state of algorihtm.
	 */
	public void reset()
	{
		processedBytes = 0;
		tail.clear();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public final void process( final Binary data )
	{
		process( data, 0, data.size() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected abstract void processBlock( Binary data, int offset );

	// -----------------------------------------------------------------------------------------------------------------
	public void process( final Binary data, int offset, int length )
	{
		if( length == 0 )
			return;

		processedBytes += length;

		if( !tail.empty() )
		{	// concatenate remainder with new data
			int part1 = Math.min( blockSize - tail.size(), length );
			tail.add( data.getDataRef(), offset, part1 );
			offset += part1;
			length -= part1;

			if( tail.size() == blockSize )
			{
				processBlock( tail, 0 );
				tail.clear();
			}
		}

		for( ; length >= blockSize; offset += blockSize, length -= blockSize )
		{
			processBlock( data, offset );
		}

		if( length != 0 )
		{	// save remainder
			tail.assign( data, offset, length );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Convenience.
	 * Calc hash of file body.
	 */
	public Binary calcFileHash( String fileName )
	{
		reset();

		try( RandomAccessFile file = new RandomAccessFile( fileName, "r" ) )
		{
			Binary buf = new Binary();
			long size = file.length();
			while( size > 0 )
			{
				buf.resize( 0x10000 );
				int chunkSize = file.read( buf.getDataRef(), 0, buf.getDataRef().length );
				MUST( chunkSize > 0, "Error while hashing file " + fileName );
				buf.resize( chunkSize );
				process( buf );
				size -= chunkSize;
			}
		}
		catch( IOException ex )
		{
			THROW( ex.toString() );
		}
		return getHash();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Resets state.
	 * @return hash of all processed data.
	 */
	public abstract Binary getHash();
	
	// -----------------------------------------------------------------------------------------------------------------
	@Override
	/**
	 * Create new object of same class without current state.
	 */
	public abstract IHash clone();

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Create new object of same class WITH current state.
	 */
	public abstract IHash cloneState();
	
	// -----------------------------------------------------------------------------------------------------------------
	protected IHash cloneStateBase()
	{
		IHash cloned = this.clone();
		MUST( cloned.blockSize == this.blockSize, "Wrong implementation of cloneState" );
		cloned.tail = this.tail.clone();
		cloned.processedBytes = this.processedBytes;
		return cloned;
	}
}
