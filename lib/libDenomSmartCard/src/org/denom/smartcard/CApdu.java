// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import java.util.Arrays;
import java.util.Locale;

import org.denom.*;
import org.denom.log.*;
import org.denom.format.*;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

/**
 * Командное APDU для карты. ISO 7816-3, p. 12.1.1.
 */
public class CApdu
{
	/**
	 * Максимальный размер ожидаемого ответа.
	 */
	public static final int MAX_NE = 256;

	/**
	 * Класс команды.
	 */
	public int cla;

	/**
	 * Код команды.
	 */
	public int ins;

	/**
	 * Первый параметр.
	 */
	public int p1;

	/**
	 * Второй параметр.
	 */
	public int p2;

	/**
	 * Командное поле данных (максимальный размер 65535 байт).
	 */
	public Binary data;

	/**
	 * Описание команды (название и т.п.).
	 */
	public String description;

	/**
	 * Запрос и ответ команды ожидается в формате BER-TLV.
	 */
	public boolean isTlvData;

	/**
	 * Возвращает размер командного поля данных {@link #data}.
	 */
	public int Nc()
	{
		return data.size();
	}

	private int Ne; // Валидные значения - 0..65536 (0x10000)

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить размер ожидаемого ответа
	 * 
	 * @return Размер
	 */
	public int getNe()
	{
		return Ne;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Установить размер ожидаемого ответа.
	 */
	public void setNe( int ne )
	{
		MUST( (ne >= 0) && (ne <= 0x10000), "Wrong Ne" );
		this.Ne = ne;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Всё инициализируется "нулевыми" значениями для последующего ручного заполнения.
	 */
	public CApdu()
	{
		clear();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать CApdu из Binary.
	 */
	public CApdu( final Binary bin )
	{
		assign( bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать CApdu из HEX строки.
	 */
	public CApdu( String hex )
	{
		this( Bin( hex ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор CApdu из заголовка [CLA, INS, P1, P2], данных и размера ожидаемого ответа.
	 * @param header - Заголовок команды [4 байта].
	 * @param data - поле данных (до 65535).
	 * @param Ne - Размер ожидаемого ответа (максимальный размер {@link #MAX_NE})
	 */
	public CApdu( final Binary header, final Binary data, int Ne )
	{
		MUST( header.size() == 4, "Wrong header size" );
		cla = header.get( 0 );
		ins = header.get( 1 );
		p1  = header.get( 2 );
		p2  = header.get( 3 );
		this.data = data.clone();
		description = "";
		setNe( Ne );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор CApdu из hex-строк: [CLA, INS, P1, P2], данные, размера ожидаемого ответа.
	 * @param header - Заголовок [4 байта].
	 * @param data - Данные (максимальный размер 65536)
	 * @param Ne - Размер ожидаемого ответа (максимальный размер {@link #MAX_NE})
	 */
	public CApdu( String header, String data, int Ne )
	{
		this( Bin( header ), Bin( data ), Ne );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор CApdu без поля данных и без Ne (case 1).
	 */
	public CApdu( int cla, int ins, int p1, int p2 )
	{
		this( cla, ins, p1, p2, Bin(), 0, "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор CApdu без поля данных, с Ne (case 2).
	 */
	public CApdu( int cla, int ins, int p1, int p2, int Ne )
	{
		this( cla, ins, p1, p2, Bin(), Ne, "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор CApdu с полем данных, без Ne (case 3).
	 */
	public CApdu( int cla, int ins, int p1, int p2, final Binary data )
	{
		this( cla, ins, p1, p2, data, 0, "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор CApdu с полем данных и Ne (case 4).
	 */
	public CApdu( int cla, int ins, int p1, int p2, final Binary data, int Ne )
	{
		this( cla, ins, p1, p2, data, Ne, "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор CApdu.
	 * @param description - Текстовое описание команды.
	 */
	public CApdu( int cla, int ins, int p1, int p2, final Binary data, int Ne, String description )
	{
		MUST( Int.isU8( cla ) && Int.isU8( ins ) && Int.isU8( p1 ) && Int.isU8( p2 )
				&& Int.isU16( data.size() ), "Wrong CApdu params" );

		this.cla = cla;
		this.ins = ins;
		this.p1 = p1;
		this.p2 = p2;
		this.data = data.clone();
		setNe( Ne );
		this.description = description;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Парсинг байтового массива, считая что это CApdu, и заполнение соответствующих полей объекта.
	 */
	public void assign( final Binary bin )
	{
		forceExtMode = false;

		int sz = bin.size();

		MUST( sz >= 4, "Wrong Command APDU" );

		this.cla = bin.get( 0 );
		this.ins = bin.get( 1 );
		this.p1  = bin.get( 2 );
		this.p2  = bin.get( 3 );
		this.data = Bin();
		Ne = 0;
		description = "";

		if( sz == 4 )
		{
			// CASE 1 - данных нет, Le нет: данные очищены при инициализации, Ne обнулено при инициализации
			return;
		}

		int b4 = bin.get( 4 );
		if( sz == 5 )
		{
			// CASE 2S - нет данных, Le 1-байтовое: данные очищены при инициализации
			Ne = (b4 != 0) ? b4 : 0x100; // C(5)
			return;
		}

		// Длина CAPDU > 5 байт

		// Анализируем C(5) на равенство 0
		if( b4 != 0 ) // C(5) != 0
		{
			// В этом случае Lc всегда 1 байт, либо APDU некорректно
			int dataSize = b4;
			MUST( (sz == 5 + dataSize) || (sz == 6 + dataSize), "Wrong Command APDU. Wrong Lc?" );

			this.data = bin.slice( 5, dataSize );
			if( sz == (6 + dataSize) )
			{
				// CASE 4S - размер данных 1-байтовый, Le 1 байт: данные уже записаны выше
				int ne = bin.get( 5 + dataSize );
				this.Ne = (ne != 0) ? ne : 0x100;
			}
			// иначе (sz == 5 + dataSize)  -  n == 5+C(5), тогда это
			// CASE 3S - размер данных 1-байтовый, Le нет: данные записаны выше, Ne обнулено при инициализации

			return;
		}

		// C(5) == 0 - поля Lc и Le если есть, то в расширенном формате
		forceExtMode = true;
		if( sz == 7 )
		{
			// CASE 2E - данных нет, Le 3 байта, первый байт 0
			// данные очищены при инициализации
			int ne = (bin.get( 5 ) << 8) | bin.get( 6 );
			this.Ne = (ne != 0) ? ne : 0x10000;
			return;
		}

		// В C(6)C(7) задано 2-байтовое Lc != 0
		MUST( sz > 7, "Incorrect Command APDU" );

		int dataSize = (bin.get( 5 ) << 8) | bin.get( 6 );
		MUST( (sz == 7 + dataSize) || (sz == 9 + dataSize), "Wrong Command APDU. Wrong Lc?" );
		this.data = bin.slice( 7, dataSize );
		if( sz == 9 + dataSize )
		{
			// CASE 4E - размер данных 2-байтовый, Le 2 байта: данные записаны выше
			int ne = (bin.get( 7 + dataSize ) << 8) | bin.get( 8 + dataSize );
			this.Ne = (ne != 0) ? ne : 0x10000;
		}
		// иначе (sz == 7 + dataSize)
		// CASE 3E - размер данных 2-байтовый, Le нет: данные заданы выше, Ne обнулено при инициализации		
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Занулить все поля командного APDU.
	 */
	public void clear()
	{
		this.cla = 0;
		this.ins = 0;
		this.p1 = 0;
		this.p2 = 0;
		this.data = Bin();
		setNe( 0 );
		this.description = "";
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать копию.
	 */
	public CApdu clone()
	{
		return new CApdu( cla, ins, p1, p2, data, Ne, description );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Нужно ли представлять это CApdu в расширенном формате?
	 */
	public boolean isExtended()
	{
		return (this.data.size() > 255) || (Ne > 256) || forceExtMode;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Список случаев (Case) по стандарту.
	 */
	public static enum Case
	{
		CASE_1, CASE_2S, CASE_2E, CASE_3S, CASE_3E, CASE_4S, CASE_4E
	};

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить Case команды.
	 */
	public Case getCase()
	{
		// Extended cases
		if( isExtended() )
		{
			if( data.size() != 0 )
			{
				return (Ne != 0) ? Case.CASE_4E : Case.CASE_3E;
			}
			return (Ne != 0) ? Case.CASE_2E : Case.CASE_1;
		}

		// Short CApdu
		if( data.size() != 0 )
		{
			return (Ne != 0) ? Case.CASE_4S : Case.CASE_3S;
		}
		return (Ne != 0) ? Case.CASE_2S : Case.CASE_1;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить в байт CLA номер логического канала.
	 * До вызова метода, поле cla должно быть с 0 каналом.
	 * @param logicalChannel Номер логического канала - от 0 до 19.
	 * Если номер канала > 3, то будет взведён также бит 0x40.
	 * @return this.
	 */
	public static int addLogicalChannel( int cla, int logicalChannel )
	{
		MUST( logicalChannel >= 0 && logicalChannel <= 19, "Wrong logical channel number" );
		if( logicalChannel < 4 )
		{
			cla |= logicalChannel;
		}
		else
		{
			cla |= (logicalChannel - 4) | 0x40;
		}
		return cla;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public CApdu addLogicalChannel( int logicalChannel )
	{
		cla = addLogicalChannel( cla, logicalChannel );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает номер логического канала, закодированный в байте cla.
	 * Для некорректного cla возвращается 0.
	 * @return номер канала.
	 */
	public static int getLogicalChannel( int cla )
	{
		if( (cla == 0xFF) || ((cla & 0xE0) == 0x20) )
			return 0;
		return ((cla & 0x40) != 0) ? ((cla & 0x0F) + 4) : (cla & 0x03);
	}

	// -----------------------------------------------------------------------------------------------------------------
	public int getLogicalChannel()
	{
		return getLogicalChannel( cla );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Убрать из cla информацию о логическом канале.
	 * обнуляются младшие 2 бита (базовые) или 4 бита и бит 0x40 (extended)
	 * @return cla без номера канала
	 */
	public static int clearLogicalChannel( int cla )
	{
		return ((cla & 0x40) != 0) ? (cla & 0xB0) : (cla & 0xFC);
	}

	// -----------------------------------------------------------------------------------------------------------------
	public int clearLogicalChannel()
	{
		return ((cla & 0x40) != 0) ? (cla & 0xB0) : (cla & 0xFC);
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Закодировать командное APDU в каноническую форму (в виде байтовой строки по стандарту ISO
	 * 7816-3, п. 12.1.1).
	 * 
	 * @return Закодированное командное APDU
	 */
	public Binary toBin()
	{
		MUST( (data.size() <= 0xFFFF) && (Ne >= 0) && (Ne <= 0x10000), "Wrong sizes in CApdu" );
		Binary result = new Binary();
		result.reserve( 9 + data.size() );
		// Header
		result.add( this.cla );
		result.add( this.ins );
		result.add( this.p1 );
		result.add( this.p2 );

		// Lc Field 
		final int sz = data.size();
		if( sz != 0 )
		{
			if( isExtended() )
			{
				result.add( 0 );
				result.add( sz >> 8 );
			}
			result.add( sz );

			// Data field
			result.add( data );
		}

		// Le Field
		if( Ne != 0 )
		{
			if( isExtended() )
			{
				if( sz == 0 )
				{
					result.add( 0 );
				}
				result.add( Ne >> 8 );
			}
			result.add( Ne & 0xFF );
		}

		return result;
	}

	// ---------------------------------------------------------------------------------------------------------------------
	static void printFieldAsTLV( final Binary data, ILog log, int color, int lineShift, String shiftStr )
	{
		if( (data.size() > 3) && BerTLV.isTLVList( data ) )
		{
			log.write( color, shiftStr );
			log.writeln( color, "- - - - - - - - - -  As BER-TLV:  - - - - - - - - - -" );
			log.writeln( color, new BerTLVList( data ).toString( lineShift) );
			log.writeln( color, "- - - - - - - - - - - - - - - - - - - - - - - - - - -" );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Напечатать CApdu в лог.
	 * @param lineShift - Смещение каждой строки.
	 */
	public void print( ILog log, int colorBytes, int colorDescription, int lineShift )
	{
		if( log instanceof LogDummy ) return;

		String shiftStr = "";
		if( lineShift > 0 )
		{
			char[] arr = new char[ lineShift ];
			Arrays.fill( arr, ' ' );
			shiftStr = new String( arr );
		}

		if( (description != null) && (description.length() != 0) )
		{
			log.writeln( colorDescription, shiftStr + description );
		}

		log.writeln( colorBytes, shiftStr + "CLA  INS   P1   P2     Ne" );
		log.writeln( colorBytes, String.format( Locale.US, "%s %02X   %02X   %02X   %02X     %6$d  (0x%6$X)",
				shiftStr, cla, ins, p1, p2, Ne ) );

		if( !data.empty() )
		{
			log.writeln( colorBytes, String.format( Locale.US, "%1$sData: %2$d (0x%2$X)", shiftStr, data.size() ) );
			log.writeln( colorBytes, data.Hex( 1, 8, 32, lineShift ) );

			if( isTlvData )
				printFieldAsTLV( data, log, colorBytes, lineShift, shiftStr );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private boolean forceExtMode = false;
}
