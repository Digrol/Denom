// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt.hash;

import org.denom.Binary;
import java.util.Arrays;

import static java.lang.Integer.rotateLeft;

/**
 * Cryptographic hash function RIPEMD-160.
 */
public class RIPEMD160 extends IHash
{
	public final static int HASH_SIZE = 20;

	private final static int BLOCK_SIZE = 64;

	private int[] X = new int[ 16 ];
	private int[] H = new int[ 5 ];

	// -----------------------------------------------------------------------------------------------------------------
	public RIPEMD160()
	{
		super( BLOCK_SIZE );
		reset();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String name()
	{
		return "RIPEMD-160";
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public int size()
	{
		return HASH_SIZE;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public RIPEMD160 clone()
	{
		return new RIPEMD160();
	}


	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public RIPEMD160 cloneState()
	{
		RIPEMD160 cloned = (RIPEMD160)this.cloneStateBase();
		cloned.H = Arrays.copyOf( this.H, this.H.length );
		return cloned;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void reset()
	{
		super.reset();
		H[0] = 0x67452301;
		H[1] = 0xefcdab89;
		H[2] = 0x98badcfe;
		H[3] = 0x10325476;
		H[4] = 0xc3d2e1f0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary getHash()
	{
		finish();

		Binary hash = new Binary( HASH_SIZE );
		for( int i = 0; i < H.length; ++i )
			hash.setIntLE( i << 2, H[ i ] );

		reset();
		return hash;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void finish()
	{
		tail.add( 0x80 );

		if( tail.size() > 56 )
		{	// no room for length
			tail.resize( BLOCK_SIZE );
			processBlock( tail, 0 );
			tail.clear();
		}

		tail.resize( BLOCK_SIZE );
		tail.setLongLE( tail.size() - 8, processedBytes << 3 );
		processBlock( tail, 0 );
	}


	// -----------------------------------------------------------------------------------------------------------------
	protected void processBlock( Binary data, int offset )
	{
		byte[] buf = data.getDataRef();
		for( int j = 0; j < 16; j++, offset += 4 )
		{
			X[ j ] =   (buf[ offset ] & 0xff)
					| ((buf[ offset + 1 ] & 0xff) << 8)
					| ((buf[ offset + 2 ] & 0xff) << 16)
					|  (buf[ offset + 3 ] << 24);
		}

		int al = H[0];
		int bl = H[1];
		int cl = H[2];
		int dl = H[3];
		int el = H[4];

		int ar = H[0];
		int br = H[1];
		int cr = H[2];
		int dr = H[3];
		int er = H[4];

		// Rounds 0-15
		// left
		al = rotateLeft(al + (bl ^ cl ^ dl) + X[ 0], 11) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + (al ^ bl ^ cl) + X[ 1], 14) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + (el ^ al ^ bl) + X[ 2], 15) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + (dl ^ el ^ al) + X[ 3], 12) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + (cl ^ dl ^ el) + X[ 4],  5) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + (bl ^ cl ^ dl) + X[ 5],  8) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + (al ^ bl ^ cl) + X[ 6],  7) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + (el ^ al ^ bl) + X[ 7],  9) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + (dl ^ el ^ al) + X[ 8], 11) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + (cl ^ dl ^ el) + X[ 9], 13) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + (bl ^ cl ^ dl) + X[10], 14) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + (al ^ bl ^ cl) + X[11], 15) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + (el ^ al ^ bl) + X[12],  6) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + (dl ^ el ^ al) + X[13],  7) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + (cl ^ dl ^ el) + X[14],  9) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + (bl ^ cl ^ dl) + X[15],  8) + el; cl = rotateLeft(cl, 10);
		// right
		ar = rotateLeft(ar + (br ^ (cr | ~dr)) + X[ 5] + 0x50a28be6,  8) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + (ar ^ (br | ~cr)) + X[14] + 0x50a28be6,  9) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + (er ^ (ar | ~br)) + X[ 7] + 0x50a28be6,  9) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + (dr ^ (er | ~ar)) + X[ 0] + 0x50a28be6, 11) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + (cr ^ (dr | ~er)) + X[ 9] + 0x50a28be6, 13) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + (br ^ (cr | ~dr)) + X[ 2] + 0x50a28be6, 15) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + (ar ^ (br | ~cr)) + X[11] + 0x50a28be6, 15) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + (er ^ (ar | ~br)) + X[ 4] + 0x50a28be6,  5) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + (dr ^ (er | ~ar)) + X[13] + 0x50a28be6,  7) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + (cr ^ (dr | ~er)) + X[ 6] + 0x50a28be6,  7) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + (br ^ (cr | ~dr)) + X[15] + 0x50a28be6,  8) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + (ar ^ (br | ~cr)) + X[ 8] + 0x50a28be6, 11) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + (er ^ (ar | ~br)) + X[ 1] + 0x50a28be6, 14) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + (dr ^ (er | ~ar)) + X[10] + 0x50a28be6, 14) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + (cr ^ (dr | ~er)) + X[ 3] + 0x50a28be6, 12) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + (br ^ (cr | ~dr)) + X[12] + 0x50a28be6,  6) + er; cr = rotateLeft(cr, 10);

		// Rounds 16-31
		// left
		el = rotateLeft(el + ((al & bl) | (~al & cl)) + X[ 7] + 0x5a827999,  7) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + ((el & al) | (~el & bl)) + X[ 4] + 0x5a827999,  6) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + ((dl & el) | (~dl & al)) + X[13] + 0x5a827999,  8) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + ((cl & dl) | (~cl & el)) + X[ 1] + 0x5a827999, 13) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + ((bl & cl) | (~bl & dl)) + X[10] + 0x5a827999, 11) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + ((al & bl) | (~al & cl)) + X[ 6] + 0x5a827999,  9) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + ((el & al) | (~el & bl)) + X[15] + 0x5a827999,  7) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + ((dl & el) | (~dl & al)) + X[ 3] + 0x5a827999, 15) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + ((cl & dl) | (~cl & el)) + X[12] + 0x5a827999,  7) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + ((bl & cl) | (~bl & dl)) + X[ 0] + 0x5a827999, 12) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + ((al & bl) | (~al & cl)) + X[ 9] + 0x5a827999, 15) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + ((el & al) | (~el & bl)) + X[ 5] + 0x5a827999,  9) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + ((dl & el) | (~dl & al)) + X[ 2] + 0x5a827999, 11) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + ((cl & dl) | (~cl & el)) + X[14] + 0x5a827999,  7) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + ((bl & cl) | (~bl & dl)) + X[11] + 0x5a827999, 13) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + ((al & bl) | (~al & cl)) + X[ 8] + 0x5a827999, 12) + dl; bl = rotateLeft(bl, 10);

		// right
		er = rotateLeft(er + ((ar & cr) | (br & ~cr)) + X[ 6] + 0x5c4dd124,  9) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + ((er & br) | (ar & ~br)) + X[11] + 0x5c4dd124, 13) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + ((dr & ar) | (er & ~ar)) + X[ 3] + 0x5c4dd124, 15) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + ((cr & er) | (dr & ~er)) + X[ 7] + 0x5c4dd124,  7) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + ((br & dr) | (cr & ~dr)) + X[ 0] + 0x5c4dd124, 12) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + ((ar & cr) | (br & ~cr)) + X[13] + 0x5c4dd124,  8) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + ((er & br) | (ar & ~br)) + X[ 5] + 0x5c4dd124,  9) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + ((dr & ar) | (er & ~ar)) + X[10] + 0x5c4dd124, 11) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + ((cr & er) | (dr & ~er)) + X[14] + 0x5c4dd124,  7) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + ((br & dr) | (cr & ~dr)) + X[15] + 0x5c4dd124,  7) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + ((ar & cr) | (br & ~cr)) + X[ 8] + 0x5c4dd124, 12) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + ((er & br) | (ar & ~br)) + X[12] + 0x5c4dd124,  7) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + ((dr & ar) | (er & ~ar)) + X[ 4] + 0x5c4dd124,  6) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + ((cr & er) | (dr & ~er)) + X[ 9] + 0x5c4dd124, 15) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + ((br & dr) | (cr & ~dr)) + X[ 1] + 0x5c4dd124, 13) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + ((ar & cr) | (br & ~cr)) + X[ 2] + 0x5c4dd124, 11) + dr; br = rotateLeft(br, 10);

		// Rounds 32-47
		// left
		dl = rotateLeft(dl + ((el | ~al) ^ bl) + X[ 3] + 0x6ed9eba1, 11) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + ((dl | ~el) ^ al) + X[10] + 0x6ed9eba1, 13) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + ((cl | ~dl) ^ el) + X[14] + 0x6ed9eba1,  6) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + ((bl | ~cl) ^ dl) + X[ 4] + 0x6ed9eba1,  7) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + ((al | ~bl) ^ cl) + X[ 9] + 0x6ed9eba1, 14) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + ((el | ~al) ^ bl) + X[15] + 0x6ed9eba1,  9) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + ((dl | ~el) ^ al) + X[ 8] + 0x6ed9eba1, 13) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + ((cl | ~dl) ^ el) + X[ 1] + 0x6ed9eba1, 15) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + ((bl | ~cl) ^ dl) + X[ 2] + 0x6ed9eba1, 14) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + ((al | ~bl) ^ cl) + X[ 7] + 0x6ed9eba1,  8) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + ((el | ~al) ^ bl) + X[ 0] + 0x6ed9eba1, 13) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + ((dl | ~el) ^ al) + X[ 6] + 0x6ed9eba1,  6) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + ((cl | ~dl) ^ el) + X[13] + 0x6ed9eba1,  5) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + ((bl | ~cl) ^ dl) + X[11] + 0x6ed9eba1, 12) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + ((al | ~bl) ^ cl) + X[ 5] + 0x6ed9eba1,  7) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + ((el | ~al) ^ bl) + X[12] + 0x6ed9eba1,  5) + cl; al = rotateLeft(al, 10);
		// right
		dr = rotateLeft(dr + ((er | ~ar) ^ br) + X[15] + 0x6d703ef3,  9) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + ((dr | ~er) ^ ar) + X[ 5] + 0x6d703ef3,  7) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + ((cr | ~dr) ^ er) + X[ 1] + 0x6d703ef3, 15) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + ((br | ~cr) ^ dr) + X[ 3] + 0x6d703ef3, 11) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + ((ar | ~br) ^ cr) + X[ 7] + 0x6d703ef3,  8) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + ((er | ~ar) ^ br) + X[14] + 0x6d703ef3,  6) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + ((dr | ~er) ^ ar) + X[ 6] + 0x6d703ef3,  6) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + ((cr | ~dr) ^ er) + X[ 9] + 0x6d703ef3, 14) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + ((br | ~cr) ^ dr) + X[11] + 0x6d703ef3, 12) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + ((ar | ~br) ^ cr) + X[ 8] + 0x6d703ef3, 13) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + ((er | ~ar) ^ br) + X[12] + 0x6d703ef3,  5) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + ((dr | ~er) ^ ar) + X[ 2] + 0x6d703ef3, 14) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + ((cr | ~dr) ^ er) + X[10] + 0x6d703ef3, 13) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + ((br | ~cr) ^ dr) + X[ 0] + 0x6d703ef3, 13) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + ((ar | ~br) ^ cr) + X[ 4] + 0x6d703ef3,  7) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + ((er | ~ar) ^ br) + X[13] + 0x6d703ef3,  5) + cr; ar = rotateLeft(ar, 10);

		// Rounds 48-63
		// left
		cl = rotateLeft(cl + ((dl & al) | (el & ~al)) + X[ 1] + 0x8f1bbcdc, 11) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + ((cl & el) | (dl & ~el)) + X[ 9] + 0x8f1bbcdc, 12) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + ((bl & dl) | (cl & ~dl)) + X[11] + 0x8f1bbcdc, 14) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + ((al & cl) | (bl & ~cl)) + X[10] + 0x8f1bbcdc, 15) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + ((el & bl) | (al & ~bl)) + X[ 0] + 0x8f1bbcdc, 14) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + ((dl & al) | (el & ~al)) + X[ 8] + 0x8f1bbcdc, 15) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + ((cl & el) | (dl & ~el)) + X[12] + 0x8f1bbcdc,  9) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + ((bl & dl) | (cl & ~dl)) + X[ 4] + 0x8f1bbcdc,  8) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + ((al & cl) | (bl & ~cl)) + X[13] + 0x8f1bbcdc,  9) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + ((el & bl) | (al & ~bl)) + X[ 3] + 0x8f1bbcdc, 14) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + ((dl & al) | (el & ~al)) + X[ 7] + 0x8f1bbcdc,  5) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + ((cl & el) | (dl & ~el)) + X[15] + 0x8f1bbcdc,  6) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + ((bl & dl) | (cl & ~dl)) + X[14] + 0x8f1bbcdc,  8) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + ((al & cl) | (bl & ~cl)) + X[ 5] + 0x8f1bbcdc,  6) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + ((el & bl) | (al & ~bl)) + X[ 6] + 0x8f1bbcdc,  5) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + ((dl & al) | (el & ~al)) + X[ 2] + 0x8f1bbcdc, 12) + bl; el = rotateLeft(el, 10);
		// right
		cr = rotateLeft(cr + ((dr & er) | (~dr & ar)) + X[ 8] + 0x7a6d76e9, 15) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + ((cr & dr) | (~cr & er)) + X[ 6] + 0x7a6d76e9,  5) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + ((br & cr) | (~br & dr)) + X[ 4] + 0x7a6d76e9,  8) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + ((ar & br) | (~ar & cr)) + X[ 1] + 0x7a6d76e9, 11) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + ((er & ar) | (~er & br)) + X[ 3] + 0x7a6d76e9, 14) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + ((dr & er) | (~dr & ar)) + X[11] + 0x7a6d76e9, 14) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + ((cr & dr) | (~cr & er)) + X[15] + 0x7a6d76e9,  6) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + ((br & cr) | (~br & dr)) + X[ 0] + 0x7a6d76e9, 14) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + ((ar & br) | (~ar & cr)) + X[ 5] + 0x7a6d76e9,  6) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + ((er & ar) | (~er & br)) + X[12] + 0x7a6d76e9,  9) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + ((dr & er) | (~dr & ar)) + X[ 2] + 0x7a6d76e9, 12) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + ((cr & dr) | (~cr & er)) + X[13] + 0x7a6d76e9,  9) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + ((br & cr) | (~br & dr)) + X[ 9] + 0x7a6d76e9, 12) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + ((ar & br) | (~ar & cr)) + X[ 7] + 0x7a6d76e9,  5) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + ((er & ar) | (~er & br)) + X[10] + 0x7a6d76e9, 15) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + ((dr & er) | (~dr & ar)) + X[14] + 0x7a6d76e9,  8) + br; er = rotateLeft(er, 10);

		// Rounds 64-79
		// left
		bl = rotateLeft(bl + (cl ^ (dl | ~el)) + X[ 4] + 0xa953fd4e,  9) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + (bl ^ (cl | ~dl)) + X[ 0] + 0xa953fd4e, 15) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + (al ^ (bl | ~cl)) + X[ 5] + 0xa953fd4e,  5) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + (el ^ (al | ~bl)) + X[ 9] + 0xa953fd4e, 11) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + (dl ^ (el | ~al)) + X[ 7] + 0xa953fd4e,  6) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + (cl ^ (dl | ~el)) + X[12] + 0xa953fd4e,  8) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + (bl ^ (cl | ~dl)) + X[ 2] + 0xa953fd4e, 13) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + (al ^ (bl | ~cl)) + X[10] + 0xa953fd4e, 12) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + (el ^ (al | ~bl)) + X[14] + 0xa953fd4e,  5) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + (dl ^ (el | ~al)) + X[ 1] + 0xa953fd4e, 12) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + (cl ^ (dl | ~el)) + X[ 3] + 0xa953fd4e, 13) + al; dl = rotateLeft(dl, 10);
		al = rotateLeft(al + (bl ^ (cl | ~dl)) + X[ 8] + 0xa953fd4e, 14) + el; cl = rotateLeft(cl, 10);
		el = rotateLeft(el + (al ^ (bl | ~cl)) + X[11] + 0xa953fd4e, 11) + dl; bl = rotateLeft(bl, 10);
		dl = rotateLeft(dl + (el ^ (al | ~bl)) + X[ 6] + 0xa953fd4e,  8) + cl; al = rotateLeft(al, 10);
		cl = rotateLeft(cl + (dl ^ (el | ~al)) + X[15] + 0xa953fd4e,  5) + bl; el = rotateLeft(el, 10);
		bl = rotateLeft(bl + (cl ^ (dl | ~el)) + X[13] + 0xa953fd4e,  6) + al; dl = rotateLeft(dl, 10);
		// right
		br = rotateLeft(br + (cr ^ dr ^ er) + X[12],  8) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + (br ^ cr ^ dr) + X[15],  5) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + (ar ^ br ^ cr) + X[10], 12) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + (er ^ ar ^ br) + X[ 4],  9) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + (dr ^ er ^ ar) + X[ 1], 12) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + (cr ^ dr ^ er) + X[ 5],  5) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + (br ^ cr ^ dr) + X[ 8], 14) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + (ar ^ br ^ cr) + X[ 7],  6) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + (er ^ ar ^ br) + X[ 6],  8) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + (dr ^ er ^ ar) + X[ 2], 13) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + (cr ^ dr ^ er) + X[13],  6) + ar; dr = rotateLeft(dr, 10);
		ar = rotateLeft(ar + (br ^ cr ^ dr) + X[14],  5) + er; cr = rotateLeft(cr, 10);
		er = rotateLeft(er + (ar ^ br ^ cr) + X[ 0], 15) + dr; br = rotateLeft(br, 10);
		dr = rotateLeft(dr + (er ^ ar ^ br) + X[ 3], 13) + cr; ar = rotateLeft(ar, 10);
		cr = rotateLeft(cr + (dr ^ er ^ ar) + X[ 9], 11) + br; er = rotateLeft(er, 10);
		br = rotateLeft(br + (cr ^ dr ^ er) + X[11], 11) + ar; dr = rotateLeft(dr, 10);

		dr += cl + H[1];
		H[1] = H[2] + dl + er;
		H[2] = H[3] + el + ar;
		H[3] = H[4] + al + br;
		H[4] = H[0] + bl + cr;
		H[0] = dr;
	}

}
