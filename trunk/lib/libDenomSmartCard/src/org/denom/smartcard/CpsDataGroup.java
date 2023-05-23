// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.*;

import static org.denom.Ex.*;

/**
 * Группа данных, передаваемая при персонализации приложений EMV
 * по спецификации EMV CPS, в команде STORE DATA.
 */
public final class CpsDataGroup
{
	/**
	 * Идентификатор группы данных.
	 */
	public int dgi;

	/**
	 * Поле данных. Формат и содержимое зависит от группы данных.
	 */
	public final Binary data;
	
	/**
	 * Описание назначения группы данных.
	 */
	public String description;
	
	/**
	 * Поле данных должно быть зашифровано на ключе DEK,
	 * в режиме ECB, No Align.
	 */
	public boolean needEncryption;
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param data - данные копируются в объект.
	 */
	public CpsDataGroup( int dgi, final Binary value, String description )
	{
		MUST( Int.isU16( dgi ), "Too large DGI, more than 2 bytes" );
		this.dgi = dgi;
		this.data = value.clone();
		this.description = description;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param data - данные копируются в объект.
	 */
	public CpsDataGroup( int dgi, final Binary data, boolean needEncryption, String description )
	{
		MUST( Int.isU16( dgi ), "Too large DGI, more than 2 bytes" );
		this.dgi = dgi;
		this.data = data.clone();
		this.description = description;
		this.needEncryption = needEncryption;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать группу данных в байтовый массив, для передачи в команде STORE DATA.
	 */
	public Binary serialize()
	{
		Binary res = new Binary().reserve( data.size() + 5 );
		
		res.addU16( dgi );

		if( data.size() < 255 )
		{
			res.add( data.size() );
		}
		else
		{
			res.add( 0xFF );
			res.addU16( data.size() );
		}

		res.add( data );

		return res;
	}

}
