// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.sharim;

import java.util.*;

import org.denom.Binary;
import org.denom.format.*;

/**
 * Шара.
 * Каталог, к которому разрешен удалённый доступ по протоколу "Sharim".
 */
public final class SharedDir
{
	/**
	 * Имя Шары. Для передачи клиенту и отображения в списках.
	 */
	public String name = "";

	/**
	 * Путь к папке в файловой системе устройства.
	 */
	public String path = "";

	/**
	 * Произвольная строка с описанием, к примеру: зачем и для кого эта Шара.
	 */
	public String comment = "";

	/**
	 * Шара активна (true) - значит, при подключении к серверу она будет доступна согласно заданного списка доступа.
	 * Неактивна (false) - шара будет не видна и недоступна при подключении к ресурсу.
	 * Для удобства при использовании ПО. Чтобы настраивать подключение, а "включать" и "выключать", не удаляя
	 * каждый раз из списка шар и не задавать каждый раз список доступа.
	 */
	public boolean active = false;

	// -----------------------------------------------------------------------------------------------------------------
	// Разграничение доступа к шаре.
	// -----------------------------------------------------------------------------------------------------------------

	/**
	 * Список публичных ключей, для которых разрешён доступ. Остальным - запрещён.
	 * Если булевский флаг = false, то доступ на чтение, если true - то полный доступ.
	 */
	public Map<Binary, Boolean> accessList = new HashMap<>();

	/**
	 * Может ли кто угодно читать.
	 */
	public boolean anyoneRead = false;

	/**
	 * Может ли кто угодно менять содержимое каталога.
	 * При полном доступе можно также и читать, соответственно нет смыла взводить этот флаг и не взводить AnyoneRead.
	 */
	public boolean anyoneFull = false;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Все поля пустые. Для последующей инициализации.
	 */
	public SharedDir() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Доступ никому не разрешён, шара неактивна.
	 */
	public SharedDir( String shareName, String path, String comment )
	{
		this.name = shareName;
		this.path = path;
		this.comment = comment;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean haveReadAccess( Binary userPublicKey )
	{
		if( this.anyoneRead )
			return true;

		Boolean access = accessList.get( userPublicKey );
		return access != null;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public SharedDir clone()
	{
		SharedDir copy = new SharedDir();
		copy.name = this.name;
		copy.path = this.path;
		copy.comment = this.comment;
		copy.active = this.active;

		for( Map.Entry<Binary, Boolean> entry : this.accessList.entrySet() )
		{
			copy.accessList.put( entry.getKey().clone(), entry.getValue().booleanValue() );
		}
		copy.anyoneRead = this.anyoneRead;
		copy.anyoneFull = this.anyoneFull;

		return copy;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public JSONObject toJSON()
	{
		JSONObject jo = new JSONObject();
		jo.put( "Name", name );
		jo.put( "Path", path );
		jo.put( "Comment", comment );
		jo.put( "Active", active );
		jo.put( "Anyone Read", anyoneRead );
		jo.put( "Anyone Full", anyoneFull );

		JSONArray ja = new JSONArray();
		for( Map.Entry<Binary, Boolean> entry : this.accessList.entrySet() )
		{
			JSONObject jj = new JSONObject();
			jj.put( "Public Key", entry.getKey() );
			jj.put( "Full Access", entry.getValue() );
			ja.put( jj );
		}
		jo.put( "Access List", ja );

		return jo;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return this
	 */
	public SharedDir fromJSON( JSONObject jo )
	{
		name = jo.getString( "Name" );
		path = jo.getString( "Path" );
		comment = jo.getString( "Comment" );
		active = jo.getBoolean( "Active" );
		anyoneRead = jo.getBoolean( "Anyone Read" );
		anyoneFull = jo.getBoolean( "Anyone Full" );

		accessList.clear();
		JSONArray ja = jo.getJSONArray( "Access List" );
		for( int i = 0; i < ja.length(); ++i )
		{
			JSONObject jj = ja.getJSONObject( i );
			Binary publicKey = jj.getBinary( "Public Key" );
			boolean fullAccess = jj.getBoolean( "Full Access" );
			accessList.put( publicKey, fullAccess );
		}

		return this;
	}
}
