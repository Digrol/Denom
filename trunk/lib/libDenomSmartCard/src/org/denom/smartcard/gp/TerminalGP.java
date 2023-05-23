// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.gp;

import org.denom.*;
import org.denom.log.*;
import org.denom.format.BerTLV;
import org.denom.crypt.*;
import org.denom.crypt.hash.SHA1;

import org.denom.smartcard.*;

import static org.denom.Ex.*;
import static org.denom.Binary.*;

/**
 * Использование карточного приложения - домен безопасности GlobalPlatform (Security Domain).

 * APDU лог по умолчанию не пишется, даже если задан для ридера, т.к. редко нужен при работе с доменом.
 * Включить можно принудительно, методом enableApduLog.
 * 
 * SecurityModule, если задан, должен быть инициализирован.
 */
public class TerminalGP
{
	/**
	 * Ридер, с которым работает терминал.
	 * Методы терминала считают, что карта вставлена, питание на карту подано.
	 */
	private CardReader cr;

	/**
	 * В этот лог терминал пишет сообщения и производимых действиях.
	 */
	private ILog log;

	/**
	 * AID домена. Может быть пустой, тогда терминал попытается выбрать один из известных ISD.
	 */
	private final Binary aid = new Binary();

	/**
	 * AID последнего выбранного приложения.
	 * Может отличаться от AID-а в поле this.aid, в случае тестового домена и выбора домена по частичному совпадению.
	 */
	private final Binary aidLastSelected = new Binary();

	/**
	 * Модуль безопасности с ключами домена, для инициализации SM c доменом.
	 * Может быть null - терминал попробует использовать известные тестовые ключи.
	 */
	private ISecurityModuleGP securityModule = null;

	/**
	 * Если взведён, то cr будет печатать в свой apduLog, иначе - нет.
	 */
	private boolean printApdu = false;


	/**
	 * Версия ключей домена карты
	 */
	private int keysVersion = 0; // по умолчанию

	private int secLevel = GP.SecLevel.CMAC; // Обычно домен поддерживает такой режим

	// -----------------------------------------------------------------------------------------------------------------
	private static final int COLOR_INFO = Colors.GREEN_I;
	private static final int COLOR_WARNING = Colors.YELLOW;

	private GP_SM sm = null;

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalGP()
	{
		this.cr = new CardReaderNull();
		this.log = new LogDummy();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalGP( CardReader cr, ILog log )
	{
		this.cr = cr;
		this.log = log;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalGP setReader( CardReader cr )
	{
		this.cr = cr;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public CardReader getReader()
	{
		return cr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать лог для вывода сообщений класса о проводимых операциях.
	 */
	public final TerminalGP setLog( ILog log )
	{
		this.log = log;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public final ILog getLog()
	{
		return log;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public TerminalGP enableApduLog( boolean enable )
	{
		printApdu = enable;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean isEnabledApduLog()
	{
		return printApdu;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать AID домена, он будет использоваться в методе select().
	 * Если AID пустой, то терминал попробует выбрать один из известных ему ISD. 
	 */
	public TerminalGP setAID( Binary aid )
	{
		this.aid.assign( aid );
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getAID()
	{
		return aid.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param securityModule - Может быть null: использовать тестовые ключи.
	 */
	public TerminalGP setSecurityModule( ISecurityModuleGP securityModule )
	{
		this.securityModule = securityModule;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public ISecurityModuleGP getSecurityModule()
	{
		return securityModule;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать параметры для установки SM. См. константы в GP.SecLevel.*
	 */
	public TerminalGP setSMParams( int keysVersion, int secLevel )
	{
		this.keysVersion = keysVersion;
		this.secLevel = secLevel;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать копию объекта.
	 * В новый объект будут скопированы следующие поля:
	 *   cr, log, secModule - копируются ссылки.
	 *   aid - новые объект.
	 *   printApdu, keysVersion, secLevel - примитивные типы.
	 */
	public TerminalGP clone()
	{
		TerminalGP copy = new TerminalGP( this.cr, this.log );
		copy.securityModule = this.securityModule;

		copy.aid.assign( this.aid );
		copy.printApdu = this.printApdu;
		copy.keysVersion = this.keysVersion;
		copy.secLevel = this.secLevel;

		return copy;
	}

	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	private void tuneApduLog( String actionMessage, Runnable action )
	{
		log.write( COLOR_INFO, actionMessage );

		ILog apduLog = cr.getApduLog();
		if( !printApdu )
		{
			cr.setApduLog( null );
		}

		try
		{
			action.run();
		}
		finally
		{
			cr.setApduLog( apduLog );
			log.writeln( "" );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выбрать домен с AID-ом this.aid на карте, если AID не задан, то будет попытка
	 * выбрать один из стандартных ISD - VISA, GP, MASTERCARD, УЭК.
	 * @return - AID успешно выбранного домена, может отличаться от поля this.aid.
	 */
	public Binary select()
	{
		sm = null;

		tuneApduLog( "Select domain... ", () ->
		{
			if( aid.empty() )
			{
				aidLastSelected.assign( selectTypicalISD() );
			}
			else
			{
				Cmd( null, ApduIso.SelectAID( aid ) );
				aidLastSelected.assign( aid );
				Binary returnedAID = new BerTLV( cr.resp ).find( "6F/84" ).value;
				if( !returnedAID.empty() )
				{
					aidLastSelected.assign( returnedAID );
				}
			}
	
			log.write( COLOR_INFO, aidLastSelected.Hex() );
		} );

		return aidLastSelected;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выбрать один из стандартных доменов - VISA, GP, MASTERCARD, УЭК.
	 */
	private Binary selectTypicalISD()
	{
		Binary aid = AID.ISD_VISA_OPENPLATFORM;
		Cmd( null, ApduIso.SelectAID( aid ), RApdu.ST_ANY );
		if( cr.rapdu.isOk() )
			return aid;
		
		aid = AID.ISD_GLOBAL_PLATFORM;
		Cmd( null, ApduIso.SelectAID( aid ), RApdu.ST_ANY );
		if( cr.rapdu.isOk() )
			return aid;

		aid = AID.ISD_MASTERCARD;
		Cmd( null, ApduIso.SelectAID( aid ), RApdu.ST_OK );
		return aid;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void connectTestDomain( int keyVersion, int secLevel )
	{
		Binary hostChallenge = Bin().random( 8 );

		Cmd( null, ApduGP.InitializeUpdate( hostChallenge, keyVersion ) );

		// Подбор ключей
		GP_SM.SessionKeys sessionKeys = null;
		for( Binary[] curKeys : GP.TEST_SD_KEYS )
		{
			Binary encKey = curKeys[ 0 ].clone();
			Binary macKey = curKeys.length > 1 ? curKeys[ 1 ].clone() : encKey.clone();
			Binary dekKey = curKeys.length > 2 ? curKeys[ 2 ].clone() : encKey.clone();

			sessionKeys = GP_SM.genSessionKeys( encKey, macKey, dekKey, hostChallenge, cr.rapdu.response );
			if( sessionKeys != null )
			{	// Нашли подходящие ключи
				break;
			}
		}

		Ex.MUST( sessionKeys != null, "Тестовые ключи не подходят к выбранному домену: " + aidLastSelected.Hex() );

		sm = new GP_SM();
		CApdu ap = GP_SM.formExtAuth( cr.rapdu.response, secLevel, hostChallenge, sessionKeys, sm );
		Cmd( null, ap );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Селектирует домен и инициализирует с ним SM на известных тестовых ключах или с помощью SecurityModule.
	 * Параметры SM задаются в setSMParams().
	 * @return - инициализированный объект SM.
	 */
	public GP_SM connectOnly()
	{
		tuneApduLog( "Connect domain... ", () ->
		{
			if( securityModule != null )
			{
				try
				{
					sm = GP_SM.open( cr, keysVersion, secLevel, securityModule );
				}
				catch( Throwable ex )
				{
					THROW( "Can't open SM with Security Module. " + ex.toString() );
				}
			}
			else
			{
				connectTestDomain( keysVersion, secLevel );
			}

			log.write( COLOR_INFO, "OK" );
		} );
		return sm;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Селектирует домен и инициализирует с ним SM, см. connectOnly().
	 * @return - инициализированный объект SM.
	 */
	public GP_SM connect()
	{
		select();
		return connectOnly();
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean deleteOnly( final Binary aid )
	{
		Int ok = new Int( 0 );

		tuneApduLog( "Delete " + aid.Hex() + "... ", () ->
		{
			Cmd( sm, ApduGP.Delete( aid, GP.DelMode.OBJECT_WITH_DEPS ), RApdu.ST_ANY );
			if( !cr.rapdu.isOk() )
			{
				Cmd( sm, ApduGP.Delete( aid, GP.DelMode.OBJECT ), RApdu.ST_ANY );
			}

			if( cr.rapdu.isOk() )
			{
				log.write( COLOR_INFO, "OK" );
				ok.val = 1;
			}
			else
			{
				log.write( COLOR_WARNING, "Failed. Status: 0x" + Num_Bin( cr.rapdu.status, 2 ).Hex() );
			}
		} );

		return ok.val == 1;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Удалить пакет или инстанс апплета.
	 * Пробуем удалять сначала с флагом GP_DEL_OBJECT, потом GP_DEL_OBJECT_WITH_DEPS,
	 * т.к. для одних карт нужен один режим, для других - другой.
	 * @param aid - AID удаляемого пакета или инстанса апплета.
	 * @return true, если удаление прошло успешно, иначе - false.
	 */
	public boolean delete( final Binary aid )
	{
		this.connect();
		return deleteOnly( aid );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean delete( final String aid )
	{
		this.connect();
		return deleteOnly( Bin( aid ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Загрузить пакет в домен.
	 * @param keyDap - Ключ для DAP верификации: если требуется - 16 байт, иначе пустой или null.
	 */
	public void loadOnly( JC_Cap cap, Binary keyDap )
	{
		tuneApduLog( "Load package " + cap.packageAID.Hex() + "... ", () ->
		{
			Binary data = cap.toBinary( false );
			int size = data.size();
	
			Binary hash = Bin();
			Binary dap = Bin();
			if( (keyDap != null) && !keyDap.empty() )
			{
				hash = new SHA1().calc( data );
				dap = new DES2_EDE( keyDap ).calcCCS( hash, AlignMode.BLOCK, CCSMode.FAST );
			}
	
			Cmd( sm, ApduGP.InstallForLoad( cap.packageAID, this.aidLastSelected, hash ), RApdu.ST_ANY );
			if( !cr.rapdu.isOk() )
			{	// На некоторых картах, например, ST-PAY, ожидается, что AID домена - пустой.
				Cmd( sm, ApduGP.InstallForLoad( cap.packageAID, Bin(), hash ) );
			}
	
			int block_num = 0;
			int offset = 0;
	
			while( offset < size )
			{
				int part_size = Math.min( 220, size - offset );
				Binary part = data.slice( offset, part_size );
				offset += part_size;
	
				CApdu ap;
				if( block_num == 0 )
				{
					ap = ApduGP.LoadFirstBlock( size, part, dap );
				}
				else
				{
					ap = ApduGP.LoadNextBlock( block_num, part, offset == size );
				}
				Cmd( sm, ap );
	
				++block_num;
			}
			log.write( COLOR_INFO, "OK" );
		} );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * 1) Выбрать домен и инициализировать SM.
	 * 2) Удалить пакет, если он был загружен ранее в карту.
	 */
	public void load( JC_Cap cap, Binary keyDap )
	{
		connect();
		loadOnly( cap, null );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * 1) Выбрать домен и инициализировать SM.
	 * 2) Удалить пакет, если он был загружен ранее в карту.
	 * 3) Загрузить пакет.
	 */
	public void reload( JC_Cap cap )
	{
		connect();
		deleteOnly( cap.packageAID );
		loadOnly( cap, null );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Удобство: cap-файл автоматически подгружается из заданного файла.
	 * @param capFileName - полное имя cap-файла.
	 */
	public void reload( String capFileName )
	{
		reload( new JC_Cap( capFileName ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать инстанс приложения в карте.
	 * @param packageAid - AID пакета с приложением.
	 * @param classAid - AID класса-приложения.
	 * @param instanceAid - AID создаваемого инстанса.
	 * @param appParams - параметры инсталляции для приложения.
	 * @param sysParams - параметры инсталляции для системы.
	 */
	// -----------------------------------------------------------------------------------------------------------------
	public void installOnly( Binary packageAid, Binary classAid, Binary instanceAid, Binary appParams, Binary sysParams )
	{
		tuneApduLog( "Install (" + packageAid.Hex() + ", " + classAid.Hex() + ")  ->  " + instanceAid.Hex(), () ->
		{
			if( !appParams.empty() )
			{
				log.writeln("");
				log.write( COLOR_INFO,"    params: " + appParams.Hex() );
			}
			log.write( COLOR_INFO, "... " );

			Cmd( sm, ApduGP.InstallForInstall( packageAid, classAid, instanceAid, appParams, 0, sysParams ) );
			log.write( COLOR_INFO, "OK" );
		} );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * 1) Выбрать домен и инициализировать SM.
	 * 2) Создать инстанс с указанным AID-ом и параметрами инсталляции.
	 */
	public void install( JC_Cap cap, String instanceAidHex, Binary appParams, Binary sysParams )
	{
		connect();
		installOnly( cap.packageAID, cap.classAIDs.get( 0 ), Bin(instanceAidHex), appParams, sysParams );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void install( JC_Cap cap, String instanceAidHex, String appParamsHex, String sysParamsHex )
	{
		connect();
		installOnly( cap.packageAID, cap.classAIDs.get( 0 ), Bin(instanceAidHex), Bin(appParamsHex), Bin(sysParamsHex) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * 1) Выбрать домен и инициализировать SM.
	 * 2) Удалить пакет, если он был загружен ранее в карту.
	 * 3) Загрузить пакет.
	 * 4) Создать инстанс с указанным AID-ом и параметрами инсталляции.
	 * @param cap - Card Package, его грузим, из него берём Package AID и Class AID (единственный в пакете).
	 * @param instanceAid - AID создаваемого инстанса.
	 * @param appParams - параметры инсталляции для приложения.
	 * @param sysParams - параметры инсталляции для системы.
	 */
	// -----------------------------------------------------------------------------------------------------------------
	public void reloadAndInstall( JC_Cap cap, String instanceAidHex, String appParamsHex, String sysParamsHex )
	{
		reload( cap );
		installOnly(cap.packageAID, cap.classAIDs.get( 0 ), Bin(instanceAidHex), Bin(appParamsHex), Bin(sysParamsHex) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void reloadAndInstall( JC_Cap cap, String instanceAidHex, Binary appParams, Binary sysParams )
	{
		reload( cap );
		installOnly(cap.packageAID, cap.classAIDs.get( 0 ), Bin(instanceAidHex), appParams, sysParams );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить у выбранного домена список пакетов / приложений / доменов. 
	 * @param getStatusTarget - см.  GP.GetStatusTarget.*
	 * @return список: { AID, info }, где info - 2 байта: Life Cycle State | Privileges.
	 */
	public Arr< Pair<Binary, Binary> > getStatus( int getStatusTarget )
	{
		Arr< Pair<Binary, Binary> > res = new Arr<>( 16 );

		tuneApduLog( "Get Status 0x" + Num_Bin( getStatusTarget, 1 ).Hex() + "... ", () ->
		{
			cr.Cmd( sm, ApduGP.GetStatus( getStatusTarget, Bin() ), RApdu.ST_ANY );

			if( cr.rapdu.isOk() )
			{
				log.write( COLOR_INFO, "OK" );

				Binary resp = cr.resp;
				for( int i = 0; i < resp.size(); )
				{
					int aidLen = resp.get( i );
					i++;
					Binary aid = resp.slice( i, aidLen );
					i += aidLen;
					Binary info = resp.slice( i, 2 );
					i += 2;
					res.add( Pair.of( aid, info ) );
				}
			}
			else
			{
				log.write( COLOR_WARNING, "Failed. Status: 0x" + Num_Bin( cr.rapdu.status, 2 ).Hex() );
			}
		} );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить список пакетов и классов-апплетов в них.
	 * @return { AID пакета : AID-ы классов }.
	 *    Если у пакета нет классов, массив AID-ов классов пустой.
	 */
	public Arr< Pair<Binary, Arr<Binary>> > getPackagesAndClasses()
	{
		Arr< Pair<Binary, Arr<Binary>> > res = new Arr<>( 16 );
		
		tuneApduLog(  "Get Packages and Applet Classes... ", () ->
		{
			CApdu ap = ApduGP.GetStatus( GP.GetStatusTarget.PKG_MDLS, Bin() );
			cr.Cmd( sm, ap, RApdu.ST_ANY );
			Binary info = cr.resp.clone();

			while( cr.rapdu.status == 0x6310 )
			{
				ap.p2 = 0x01; // Next
				cr.Cmd( sm, ap, RApdu.ST_ANY );
				info.add( cr.resp );
			}

			if( !cr.rapdu.isOk() )
			{
				log.write( COLOR_WARNING, "Failed. Status: 0x" + Num_Bin( cr.rapdu.status, 2 ).Hex() );
				return;
			}

			log.write( COLOR_INFO, "Ok" );

			for( int offset = 0; offset < info.size(); )
			{
				Binary packageAid = info.slice( offset + 1, info.get( offset ) );
				offset += packageAid.size() + 3;

				int classNumber = info.get( offset++ );
				Arr<Binary> classList = new Arr<>( classNumber );
				for( int j = 0; j < classNumber; ++j )
				{
					int len = info.get( offset++ );
					classList.add( info.slice( offset, len ) );
					offset += len;
				}

				res.add( Pair.of( packageAid, classList ) );
			}
		} );
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать объекта данных с заданным тегом.
	 * Например: 0x9F7F - CPLC, поддерживается известными нам картами.
	 * Большую часть тегов, указанных в Global Platform, карты не поддерживают.
	 * 0xE0 обычно тоже возвращают - с информацией о симметричных ключах.
	 * @return ответ карты (поле value). Пустой, если GET DATA возвращает ошибку.
	 */
	public Binary getData( int tag )
	{
		Binary data = Bin();
		tuneApduLog( "Get Data, tag: " + Num_Bin( tag, 1 ).Hex() + "... ", () ->
		{
			cr.Cmd( sm, ApduGP.GetData( tag ), RApdu.ST_ANY );
			if( cr.rapdu.isOk() )
			{
				data.assign( new BerTLV( cr.resp ).value );
				log.write( COLOR_INFO, "Ok" );
			}
			else
			{
				log.write( Colors.YELLOW_I,  "Failed or absent" );
			}
			
		} );
		return data;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 *  Распарсить CPLC (Card Production Life Cycle Data).
	 *  @param cplc - значение TLV-объекта с тэгом 0x9F7F.
	 *  Формат даты: [2 байта], YDDD - десятичный numeric-формат. Y - последняя цифра года. Если Y меньше или равен 
	 *  последней цифре текущего года, то имеется в виду год текущего десятилетия, иначе - год предыдущего десятилетия.
	 *  DDD - количество дней, прошедших с 1 января года Y.
	 *  @return список из 18 параметров: { Название параметра, его значение }.
	 */
	public static Arr< Pair<String, Binary> > parseCPLC( Binary cplc )
	{
		MUST( (cplc != null) && (cplc.size() >= 0x2A), "Wrong CPLC size" );

		Arr< Pair<String, Binary> > res = new Arr<>( 18 );

		res.add( Pair.of( "IC Fabricator",              cplc.slice( 0, 2 ) ) );
		res.add( Pair.of( "IC Type",                    cplc.slice( 2, 2 ) ) );

		res.add( Pair.of( "OS ID",                      cplc.slice( 4, 2 ) ) );
		res.add( Pair.of( "OS Release Date",            cplc.slice( 6, 2 ) ) );
		res.add( Pair.of( "OS Release Level",           cplc.slice( 8, 2 ) ) );
		
		res.add( Pair.of( "IC Fabrication Date",        cplc.slice( 10, 2 ) ) );
		res.add( Pair.of( "IC Serial Number",           cplc.slice( 12, 4 ) ) );
		res.add( Pair.of( "IC Batch Identifier",        cplc.slice( 16, 2 ) ) );
		res.add( Pair.of( "IC Module Fabricator",       cplc.slice( 18, 2 ) ) );
		res.add( Pair.of( "IC Module Packaging Date",   cplc.slice( 20, 2 ) ) );
		res.add( Pair.of( "IC Manufacturer",            cplc.slice( 22, 2 ) ) );
		res.add( Pair.of( "IC Embedding Date",          cplc.slice( 24, 2 ) ) );
		res.add( Pair.of( "IC PrePersonalizer",         cplc.slice( 26, 2 ) ) );
		res.add( Pair.of( "IC PrePersonalization Date", cplc.slice( 28, 2 ) ) );
		res.add( Pair.of( "IC PrePerso Equipment ID",   cplc.slice( 30, 4 ) ) );
		res.add( Pair.of( "IC Personalizer",            cplc.slice( 34, 2 ) ) );
		res.add( Pair.of( "IC Personalization Date",    cplc.slice( 36, 2 ) ) );
		res.add( Pair.of( "IC Perso Equipment ID",      cplc.slice( 38, 4 ) ) );

		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сменить один ключ в одном из KeySet-ов домена.
	 * В KeySet-е 3 ключа для SM (могут быть и дополнительные) и байт с версией для идентификации KeySet-а.
	 * После успешного выполнения команды, байт версии сменится на заданный.
	 * @param keyId - идентификатор ключа - 1 (ENC), 2 (MAC), 3 (DEK).
	 * @param keyVersionCurrent - версия (идентификатор) KeySet-а, в котором меняем ключ. В домене ищется KeySet,
	 *   хранящий ключи с таким байтом. Если задать 0 - то будет создана НОВЫЙ KeySet.
	 * @param keyVersionNew - новая версия KeySet-а, такой идентификатор будет у KeySet-а после успешного выполнения команды.
	 *   Версию изменять не обязательно.
	 * @param keyValue - новое значение ключа.
	 */
	public void changeKey( int keyId, int keyVersionCurrent, int keyVersionNew, final Binary keyValue )
	{
		tuneApduLog( "Change Key, KeyId: " + keyId + ", KeyVersionCurrent: " + keyVersionCurrent
				+ ", KeyVersionNew: " + keyVersionNew + " ... ", () ->
		{
			MUST( keyValue.size() == DES2_EDE.KEY_SIZE, "Wrong key size, must be 16 bytes" );
			Cmd( sm, ApduGP.PutKey( keyId, 0x80, keyVersionCurrent, keyVersionNew, keyValue, sm.dekCipher.getKey() ) );
			log.write( COLOR_INFO, "OK" );
		} );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать новый KeySet для SM SCP 02.
	 * @param keyVersionNew - новая версия KeySet-а.
	 * @param keyEnc - новое значение ключа Enc.
	 * @param keyMac - новое значение ключа Mac.
	 * @param keyDek - новое значение ключа Dek.
	 */
	public void createSmKeys( int keyVersionNew, final Binary keyEnc, final Binary keyMac, final Binary keyDek )
	{
		tuneApduLog( "Create KeySet for SM, KeyVersionNew: " + keyVersionNew + " ... ", () ->
		{
			MUST( (keyEnc.size() == DES2_EDE.KEY_SIZE) && (keyMac.size() == DES2_EDE.KEY_SIZE) && (keyDek.size() == DES2_EDE.KEY_SIZE),
				"Wrong key size, must be 16 bytes" );
			Cmd( sm, ApduGP.PutKey_KeySet( 1, 0x80, 0, keyVersionNew, keyEnc, keyMac, keyDek, sm.dekCipher.getKey() ) );
			log.write( COLOR_INFO, "OK" );
		} );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сменить KeySet для SM SCP 02.
	 * @param keyVersionCurrent - идентифицирует KeySet в карте. Если = 0, то будет создан новый KeySet.
	 */
	public void changeSmKeys( int keyVersionCurrent, int keyVersionNew, final Binary keyEnc, final Binary keyMac, final Binary keyDek )
	{
		tuneApduLog( "Change KeySet for SM, KeyVersionCurrent: " + keyVersionCurrent + ", KeyVersionNew: " + keyVersionNew + " ... ", () ->
		{
			MUST( (keyEnc.size() == DES2_EDE.KEY_SIZE) && (keyMac.size() == DES2_EDE.KEY_SIZE) && (keyDek.size() == DES2_EDE.KEY_SIZE),
				"Wrong key size, must be 16 bytes" );
			Cmd( sm, ApduGP.PutKey_KeySet( 1, 0x80, keyVersionCurrent, keyVersionNew, keyEnc, keyMac, keyDek, sm.dekCipher.getKey() ) );
			log.write( COLOR_INFO, "OK" );
		} );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сменить значения ключей домена в ТЕКУЩЕМ KeySet-е (на котором установлен SM), для удобства.
	 */
	public void changeSmKeys( int keyVersionNew, final Binary keyEnc, final Binary keyMac, final Binary keyDek )
	{
		tuneApduLog( "Change KeySet for SM, KeyVersionCurrent: " + sm.keysVersion + ", KeyVersionNew: " + keyVersionNew + " ... ", () ->
		{
			MUST( (keyEnc.size() == DES2_EDE.KEY_SIZE) && (keyMac.size() == DES2_EDE.KEY_SIZE) && (keyDek.size() == DES2_EDE.KEY_SIZE),
					"Wrong key size, must be 16 bytes" );

			if( sm.keysVersion == 0xFF ) // current is initial Secure Channel KeySet
			{
				Cmd( sm, ApduGP.PutKey_KeySet( 1, 0x80, 0, keyVersionNew, keyEnc, keyMac, keyDek, sm.dekCipher.getKey() ) );
			}
			else
			{
				// Try to change 3 keys in a row, if card supports this mode.
				Cmd( sm, ApduGP.PutKey_KeySet( 1, 0x80, sm.keysVersion, keyVersionNew,
					keyEnc, keyMac, keyDek, sm.dekCipher.getKey() ), RApdu.ST_ANY );

				if( !cr.rapdu.isOk() )
				{
					// Put 3 Keys by 3 commands
					Cmd( sm, ApduGP.PutKey( 1, 0x80, sm.keysVersion, keyVersionNew, keyEnc, sm.dekCipher.getKey() ) );
					// key version already changed
					Cmd( sm, ApduGP.PutKey( 2, 0x80, keyVersionNew, keyVersionNew, keyMac, sm.dekCipher.getKey() ) );
					Cmd( sm, ApduGP.PutKey( 3, 0x80, keyVersionNew, keyVersionNew, keyDek, sm.dekCipher.getKey() ) );
				}
			}
			log.write( COLOR_INFO, "OK" );
		} );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Удобство: Сменить только значения ключей домена ТЕКУЩЕГО KeySet-а, байт версии не изменять.
	 */
	public void changeSmKeys( final Binary keyEnc, final Binary keyMac, final Binary keyDek )
	{
		int newKeyVersion = sm.keysVersion;
		if( sm.keysVersion == 0xFF ) // initial Secure Channel KeySet
		{
			newKeyVersion = 1;
		}
		changeSmKeys( newKeyVersion, keyEnc, keyMac, keyDek );
	}

	// =================================================================================================================
	private final String thisClassName = this.getClass().getName();
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Печать места вызова - вышестоящий класс.
	 */
	private void Cmd( ISM sm, CApdu capdu, int expectedStatus )
	{
		cr.callerClassName = thisClassName;
		cr.Cmd( sm, capdu, expectedStatus );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void Cmd( ISM sm, CApdu capdu )
	{
		cr.callerClassName = thisClassName;
		cr.Cmd( sm, capdu, RApdu.ST_OK );
	}

}
