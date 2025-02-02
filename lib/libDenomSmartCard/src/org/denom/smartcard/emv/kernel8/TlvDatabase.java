// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.denom.Binary;
import org.denom.format.BerTLV;
import org.denom.format.BerTLVList;
import org.denom.smartcard.emv.ITagDictionary;
import org.denom.smartcard.emv.TagInfo;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * Мап для накопления объектов данных (TLV-теги и их value) в Kernel-е во время проведения транзакции с картой.
 * EMV Сontactless Book C-8, Kernel 8 Specification v1.1.
 *     4.1. TLV Database.
 *     4.1.3. Services.
 * В рамках этого класса DB (БД) означает список (мап) хранимых объектов данных.
 * Большинство методов - это реализация "сервисов" из спецификации, раздел 4.1.3.
 * Эти методы начинаются с заглавной буквы.
 */
public class TlvDatabase
{
	public HashMap<Integer, Binary> db;

	public ITagDictionary dict;

	// -----------------------------------------------------------------------------------------------------------------
	public TlvDatabase( ITagDictionary dict )
	{
		db = new HashMap<Integer, Binary>();
		this.dict = dict;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Очистить БД.
	 * Удалить все хранимые объекты.
	 */
	public void clear()
	{
		db.clear();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void store( int tag, Binary value )
	{
		MUST( value != null, "TlvDatabase.store: Value == null" );
		db.put( tag, value );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Весь список тегов для печати
	 */
	public String toString( int offset )
	{
		Binary b  = Bin();
		for( Map.Entry<Integer, Binary> e : db.entrySet() )
			b.add( BerTLV.Tlv( e.getKey(), e.getValue() ) );

		return new BerTLVList( b ).toString( offset );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Returns TRUE if the TLV Database includes a data object with tag T.
	 */
	public boolean IsPresent( int tag )
	{
		return db.containsKey( tag );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Returns TRUE if the TLV Database does not include a data object with tag T.
	 */
	public boolean IsNotPresent( int tag )
	{
		return !db.containsKey( tag );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Returns TRUE if all of the following are true:
	 *  + IsPresent(T)
	 *  + GetLength(T) > 0
	 */
	public boolean IsNotEmpty( int tag )
	{
		Binary val = db.get( tag );
		return (val != null) && !val.empty();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Returns TRUE if all of the following are true:
	 *  + IsPresent(T)
	 *  + GetLength(T) = 0
	 */
	public boolean IsEmpty( int tag )
	{
		Binary val = db.get( tag );
		return (val != null) && val.empty();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Initialises the data object with tag T with a zero length.
	 * After initialisation, IsPresent(T) returns TRUE.
	 */
	public void Initialise( int tag )
	{
		db.put( tag, new Binary() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает TLV в сериализованном виде.
	 * Если запрашиваемого тега нет в БД, то пустой массив (не null).
	 * @param tag
	 * @return
	 */
	public Binary GetTLV( int tag )
	{
		Binary val = db.get( tag );
		if( val == null )
			return new Binary();
		return BerTLV.Tlv( tag, val );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Размер поля Value; либо -1, если тега нет в БД.
	 */
	public int GetLength( int tag )
	{
		Binary val = db.get( tag );
		if( val == null )
			return -1;
		return val.size();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Retrieves from the TLV Database the value in bytes of the data object with tag T. 
	 * Returns NULL if IsEmpty(T) OR IsNotPresent(T) returns TRUE.
	 */
	public Binary GetValue( int tag )
	{
		Binary val = db.get( tag );
		if( (val == null) || val.empty() )
			return null;
		return val;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Returns TRUE if tag T is defined in Table A.37 or if tag T is included in Proprietary Tags. 
	 */
	public boolean IsKnown( int tag )
	{
		return dict.find( tag ) != null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Возвращает тег для заданного имени (ищет в словаре).
	 * Имя должно полностью совпадать с названием в словаре. Если не найдено, то возвращается 0.
	 */
	public int TagOf( String name )
	{
		TagInfo info = dict.find( name );
		if( info == null )
			return 0;
		return info.tag;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Парсим ответ от карты и помещаем все найденные примитивные теги в БД, если тег нам известен,
	 * не задан ранее и карта имеет право его задавать.
	 * Более детально - см. спецификацию или тело метода.
	 * @return FALSE - если ответ карты не удовлетворяет всем требованиям.
	 */
	public boolean ParseAndStoreCardResponse( Binary tlvsBin )
	{
		if( !BerTLV.isTLV( tlvsBin ) )
			return false;
		BerTLV tlvMain = new BerTLV( tlvsBin );
		if( !tlvMain.isConstructed() )
			return false;

		ArrayList<BerTLV> recs = new BerTLVList( tlvsBin ).recs;

		for( int i = 0; i < recs.size(); ++i )
		{
			BerTLV curTlv = recs.get( i );
			// Добавляем все вложенные теги в конец списка.
			if( curTlv.isConstructed() )
			{
				BerTLVList innerList = new BerTLVList( curTlv.value );
				recs.addAll( innerList.recs );
			}
		}

		// Пропускаем constructed-теги и неизвестные нам.
		// Известные - добавляем в БД, если они корректной длины и карта имеет право добавлять такие теги.
		for( int i = 0; i < recs.size(); ++i )
		{
			BerTLV curTlv = recs.get( i );
			if( curTlv.isConstructed() )
				continue;
			
			int tag = curTlv.tag;
			if( !IsKnown( tag ) )
				continue;

			if( IsNotPresent( tag ) || IsEmpty( tag ) || curTlv.value.equals( GetValue( tag ) ) )
			{
				TagInfo info = dict.find( tag );
				if ( !info.fromCard || !info.isGoodLen( curTlv ) )
					return false;
				db.put( tag, curTlv.value );
			}
			else
			{
				return false;
			}
		}

		return true;
	}
}
