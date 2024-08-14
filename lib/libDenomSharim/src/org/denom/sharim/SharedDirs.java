// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.sharim;

import java.util.*;

import org.denom.*;

/**
 * Список Шар.
 */
public final class SharedDirs
{
	private Map<String, SharedDir> shares = new HashMap<>();

	// -----------------------------------------------------------------------------------------------------------------
	public SharedDirs() {}

	// -----------------------------------------------------------------------------------------------------------------
	public void addSharedDir( SharedDir newSharedDir )
	{
		shares.put( newSharedDir.name, newSharedDir );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public SharedDir getShare( String name )
	{
		return shares.get( name );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Найти все шары, которые доступны данному пользователю.
	 * Второй элемент пары - fullAccess флаг.
	 */
	public Arr< Pair<String, Boolean> > getSharesListForUser( Binary userPublicKey )
	{
		Arr<Pair<String, Boolean>> sharesList = new Arr<>();
		for(SharedDir share : shares.values() )
		{
			if( !share.active )
				continue;

			Boolean access = share.accessList.get( userPublicKey );
			if( share.anyoneFull || share.anyoneRead || access != null )
			{
				boolean fullAccess = share.anyoneFull || ((access != null) && (access.booleanValue()));
				sharesList.add( Pair.of( share.name, fullAccess ) );
			}
		}
		return sharesList;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Ссылка на список шар.
	 */
	public Map<String, SharedDir> getShares()
	{
		return this.shares;
	}
	
}
