// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.sharim;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Список команд логического уровня для приёма и передачи файлов
 */
public class SharimCommand
{
	public final static int GET_SHARES_LIST = 0xCDD00001;
	public final static int LIST_FILES      = 0xCDD00002;
	public final static int GET_FILE_INFO   = 0xCDD00003;
	public final static int GET_FILE_PART   = 0xCDD00004;
}
