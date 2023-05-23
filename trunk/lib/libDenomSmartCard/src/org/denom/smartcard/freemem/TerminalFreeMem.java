// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.freemem;

import org.denom.Binary;
import org.denom.card.*;
import org.denom.card.gp.*;

/**
 * Использование инстанса JC-апплета FreeMem.
 * Замер свободного места в EE.
 */
public class TerminalFreeMem
{
	public static final String CAP_FREEMEM = "freemem_221.cap";

	public CardReader cr;

	// Размер свободного EEPROM-а в карте.
	public int ee;

	// Размер свободной RAM (RTR).
	public int rtr;

	// Размер свободной RAM (DTR).
	public int dtr;

	// Версия JC API.
	public Binary jcVersion = new Binary();

	// Размер транзакционного буфера.
	public int trcBufSize;

	// Поддерживается ли в карте сборка мусора.
	public boolean isGCSupported;


	private JC_Cap cap;
	private String instanceAid;
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param capFileName - Полный путь к CAP-файлу с апплетом, например: "../jcFreeMem/freemem_221.cap";
	 */
	public TerminalFreeMem( String capFileName )
	{
		this.cap = new JC_Cap( capFileName );
		this.instanceAid = cap.classAIDs.get( 0 ).Hex();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalFreeMem setReader( CardReader reader )
	{
		this.cr = reader;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выяснить размеры свободного места в RAM-е и EEPROM-е и т.д, см. поля класса.<br>
	 * Инстанс селектируется здесь же.<br>
	 * Результат - в полях this.ee, this.rtr, this.dtr.<br>
	 * Если в EE свободного места больше, чем 32К, то в this.ee будет 0x7FFF.
	 * @return ссылка на себя.
	 */
	public TerminalFreeMem getInfo()
	{
		cr.Cmd( ApduIso.SelectAID( instanceAid ) );
		cr.Cmd( ApduFreeMem.GetFreeMem() );

		this.ee  = cr.resp.getU16( 0 );
		this.rtr = cr.resp.getU16( 2 );
		this.dtr = cr.resp.getU16( 4 );
		this.jcVersion  = cr.resp.slice( 6, 2 );
		this.trcBufSize = cr.resp.getU16( 8 );
		this.isGCSupported = (cr.resp.get( 10 ) == 1);

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выделять свободное место в карте, пока не останется < 32K.
	 * @return сколько байт выделено.
	 */
	public int allocEE()
	{
		cr.Cmd( ApduIso.SelectAID( instanceAid ) );

		int chunkSize = 5000;
		int allocated = 0;

		cr.Cmd( ApduFreeMem.GetFreeMem() );
		while( cr.resp.getU16( 0 ) == 0x7FFF )
		{
			cr.Cmd( ApduFreeMem.AllocEE( chunkSize ) );
			allocated += chunkSize;
			cr.Cmd( ApduFreeMem.GetFreeMem() );
		}

		return allocated;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выяснить размеры свободного места в RAM-е и EEPROM-е.<br>
	 * Если в EE свободного места больше, чем 32К, то апплетом сначала выделяются dummy массивы (по 5 КБайт),
	 * пока свободного EE не останется меньше, чем 32К. После замера вызывается GC (если поддерживается картой).
	 * Также к вычисленному свободному месту добавляется примерный размер пакета и инстанса (500 байт).
	 * Инстанс селектируется здесь же.<br>
	 * Результат - в полях this.ee, this.rtr, this.dtr, ...<br>
	 * @return Размер свободного места в EEPROM-е (не ограничено 0x7FFF).
	 */
	public int measureFreeEE()
	{
		int allocated = allocEE();

		getInfo();
		this.ee += allocated;

		cr.Cmd( ApduFreeMem.RunGC() );

		return this.ee;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Удобство: загружается пакет с апплетом JCFreeMem, создаётся инстанс, а после замеров памяти, пакет удаляется.
	 * @return Размер свободного места в EEPROM-е (не ограничено 0x7FFF).
	 */
	public int measureFreeEE( TerminalGP domain )
	{
		domain.reloadAndInstall( cap, instanceAid, "", "" );
		int freeEE = measureFreeEE();
		domain.delete( cap.packageAID );
		return freeEE;
	}

}