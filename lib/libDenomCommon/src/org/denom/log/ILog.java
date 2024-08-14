// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.log;

public interface ILog
{
	/**
	 * Записать в лог произвольный текст.
	 * @param text Текст для записи
	 */
	void write( String text );

	/**
	 * Записать в лог текст указанным цветом.
	 * @param color Цвет текста.
	 * @param text Текст для записи в лог.
	 */
	void write( int color, String text );

	/**
	 * Записать в лог произвольный текст, в конце текста будет добавлен символ перевода строки.
	 * @param text Текст для записи.
	 */
	void writeln( String text );

	/**
	 * Записать в лог произвольный текст, в конце текста будет добавлен символ перевода строки.
	 * @param text Текст для записи.
	 */
	void writeln( int color, String text );

	/**
	 * Задать цвет сообщений по умолчанию.
	 * @param color - Цвет текста по умолчанию.
	 */
	void setDefaultColor( int color );
	
	/**
	 * Задать лог, следующий в цепочке логов.
	 * Этот объект обработает сообщение и передаст его следующему в цепочке.
	 * Например для одновременного вывода сообщений и в файл, и в консоль:
	 * ILog myLog = new LogFile("file").setNext( new LogConsole() );
	 * @param log - Следующий лог или null.
	 * @return Ссылка на себя.
	 */
	ILog setNext( ILog log );
	
	/**
	 * Закрыть лог.
	 */
	void close();
}
