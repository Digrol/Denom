// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.gp;

import org.denom.*;
import org.denom.card.*;

import static org.denom.Binary.Bin;

/**
 * Утилиты для работы с доменом по GP.
 */
public class GP
{
	// Известные тестовые ключи доменов.
	public static Binary[][] TEST_SD_KEYS =
	{
		// ENC key или базовый для 3-х ключей    |        MAC Key                         |     DEK Key
		{ Bin("404142434445464748494a4b4c4d4e4f"), Bin("404142434445464748494a4b4c4d4e4f"), Bin("404142434445464748494a4b4c4d4e4f") },
		{ Bin("00112233445566778899AABBCCDDEEFF") },
		{ Bin("01010101010101010101010101010101") }, // Oberthur 5.0
		{ Bin("47454D5850524553534F53414D504C45") }, // Str_Bin("GEMXPRESSOSAMPLE")
		{ Bin("FE26675E61405D9E8326C7AD8343086E") }, // KONA-16 ?

		{ Bin("303132333435363738393A3B3C3D3E3F"), Bin("404142434445464748494a4b4c4d4e4f") }, // Микрон УЭК, Atlas ?
//		{ Bin("B18A2D16990BAC454A40AAF0CD5B17B2"), Bin("FCCDBD8B62C74603EA4C1ED404D8290F") }, // Atlas - some key
//		{ Bin("F6E1C739DFAF75E3FD8FB44D107138F7"), Bin("EE5184DE8CC23B4F5ACBEF7C941A66C5") }, // Gemalto UEC ?
	};

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 *  Ключ, часто используемый по умолчанию в доменах тестовых карт.
	 */
	public static final Binary TEST_ISD_KEY = Bin( "404142434445464748494a4b4c4d4e4f" );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Режим удаления объектов по GP, для команды DELETE.
	 */
	public static final class DelMode
	{
		/**
		 * Удаление только объекта с указанным AID-ом
		 */
		public static final int OBJECT = 0x00;

		/**
		 * Удаление пакета с указанным AID-ом
		 */
		public static final int PACKET = 0x01;

		/**
		 * Удаление объекта с указанным AID-ом и всех зависимых от него объектов.
		 */
		public static final int OBJECT_WITH_DEPS = 0x80;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Уровень безопасности GP SM.
	 */
	public static class SecLevel
	{
		public static final int NO_SM          = 0x00; // 0000 0000
		public static final int CMAC           = 0x01; // 0000 0001
		public static final int RMAC           = 0x10; // 0001 0000
	
		public static final int CMAC_RMAC      = 0x11; // 0001 0001
		public static final int CMAC_CDEC      = 0x03; // 0000 0011
		public static final int CMAC_CDEC_RMAC = 0x13; // 0001 0011
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Тип приложения для команды {@link ApduGP#GetStatus( int, Binary )} - параметр p1.
	 */
	public static final class GetStatusTarget
	{
		/**
		 * Информация об ISD
		 */
		public static final int ISD = 0x80; // 1000 0000
		/**
		 * Информация о приложениях, включая SD
		 */
		public static final int APP = 0x40; // 0100 0000
		/**
		 * Информация о загруженных на карту пакетах
		 */
		public static final int PKG = 0x20; // 0010 0000
		/**
		 * Информация о загруженных на карту пакетах и их исполняемых модулях
		 */
		public static final int PKG_MDLS = 0x10; // 0001 0000
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Тип приложения для команды {@link ApduGP#SetStatus( int, int, Binary )} - параметр p1.
	 */
	public static final class SetStatusTarget
	{
		/**
		 * ISD
		 */
		public static final int ISD = 0x80; // 1000 0000
		/**
		 * SD или приложение
		 */
		public static final int APP = 0x40; // 0100 0000
		/**
		 * SD и связанные с этим SD приложения
		 */
		public static final int SD_APPS = 0x60; // 0110 0000
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Статус приложения для команды {@link CApdu ApduGP.SetStatus( int, int, final Binary )} - параметр p2.
	 */
	public static final class AppState
	{
		/**
		 * Заблокировать
		 */
		public static final int BLOCKED = 0x80;
		/**
		 * Разблокировать
		 */
		public static final int ACTIVE = 0x00;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Удалить пакет или инстанс апплета. SD должен быть выбран, SM инициализирован. Утилита пробует
	 * удалять сначала с флагом GP_DEL_OBJECT, потом GP_DEL_OBJECT_WITH_DEPS, т.к. для один карт
	 * нужен один режим, для других - другой.
	 * 
	 * @param sm - Инициализированный объект SM.
	 * @param aid - AID удаляемой сущности.
	 * @param cmd_runner - ссылка на исполнитель команд.
	 * @return true, если удаление прошло успешно, иначе - false.
	 */
	public static boolean DeleteObject( final ISM sm, final Binary aid, CardReader cr )
	{
		cr.Cmd( sm, ApduGP.Delete( aid, DelMode.OBJECT_WITH_DEPS ), RApdu.ST_ANY );
		boolean ok = cr.rapdu.isOk();

		if( !ok )
		{
			cr.Cmd( sm, ApduGP.Delete( aid, DelMode.OBJECT ), RApdu.ST_ANY );
			ok = cr.rapdu.isOk();
		}
		return ok;
	}

}
