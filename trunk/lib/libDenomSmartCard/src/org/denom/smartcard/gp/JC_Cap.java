// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.gp;

import java.io.*;
import java.util.*;
import java.util.zip.*;
import org.denom.Binary;

import static org.denom.Ex.*;
import static org.denom.Binary.Bin;

/**
 * Загрузка, парсинг и хранение компонентов cap-файла.
 */
public class JC_Cap
{
	public static final int COMPONENT_HEADER = 1;
	public static final int COMPONENT_DIRECTORY = 2;
	public static final int COMPONENT_APPLET = 3;
	public static final int COMPONENT_IMPORT = 4;
	public static final int COMPONENT_CONSTANT_POOL = 5;
	public static final int COMPONENT_CLASS = 6;
	public static final int COMPONENT_METHOD = 7;
	public static final int COMPONENT_STATIC_FIELD = 8;
	public static final int COMPONENT_REFLOCATION = 9;
	public static final int COMPONENT_EXPORT = 10;
	public static final int COMPONENT_DESCRIPTOR = 11;
	public static final int COMPONENT_DEBUG = 12;

	/**
	 * Имена компонентов, по которым производится поиск в архиве в порядке, рекомендованном к загрузке.
	 */
	public static final String[] COMP_FILES =
	{
		"",
		"Header.cap",
		"Directory.cap",
		"Applet.cap",
		"Import.cap",
		"ConstantPool.cap",
		"Class.cap",
		"Method.cap",
		"StaticField.cap",
		"RefLocation.cap",
		"Export.cap",
		"Descriptor.cap",
		"Debug.cap"
	};

	/**
	 * Сопоставление тег -> позиция для загрузки.
	 */
	public static final int[] COMP_LOAD_ORDER = 
	{
		COMPONENT_HEADER,
		COMPONENT_DIRECTORY,
		COMPONENT_IMPORT,
		COMPONENT_APPLET,
		COMPONENT_CLASS,
		COMPONENT_METHOD,
		COMPONENT_STATIC_FIELD,
		COMPONENT_EXPORT,
		COMPONENT_CONSTANT_POOL,
		COMPONENT_REFLOCATION,
		COMPONENT_DESCRIPTOR
	};

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Список с AID-ами классов, входящих в состав пакета.
	 */
	public ArrayList<Binary> classAIDs = new ArrayList<Binary>( 1 );

	/**
	 * Список компонентов cap-файла в порядке следования идентификаторов.
	 */
	public ArrayList<Binary> components = new ArrayList<Binary>( 13 );

	/**
	 * AID пакета.
	 */
	public Binary packageAID;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Пустой конструктор для последующей инициализации.
	 */
	public JC_Cap() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать CAP-файл по заданному пути.
	 * ВНИМАНИЕ!!! Если файл не найден по заданному пути, будет попытка считать файл из репозитория.
	 */
	public JC_Cap( String capPath )
	{
		load( capPath );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать CAP-файл по заданному пути.
	 */
	public void load( String capPath )
	{
		initComponents( capPath );
		initAIDs();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вернуть пакет в бинарном виде.</br> Компоненты конкатенируются в порядке, рекомендованном к
	 * загрузке({@link #COMP_LOAD_ORDER}).
	 * 
	 * @param includeDescriptorCap
	 *            Флаг, определяющий включать ли компонент Descriptor.cap или нет
	 * @return Пакет
	 */
	public Binary toBinary( boolean includeDescriptorCap )
	{
		Binary packageCap = Bin();

		int componentsCount = COMP_LOAD_ORDER.length;
		if( !includeDescriptorCap )
		{
			--componentsCount;
		}

		for( int i = 0; i < componentsCount; ++i )
		{
			Binary component = components.get( COMP_LOAD_ORDER[i] );
			packageCap.add( component == null ? Bin() : component );
		}

		return packageCap;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void initComponents( String capPath )
	{
		components.clear();

		for( int i = 0; i < 13; ++i )
		{
			components.add( null );
		}

		try
		{
			ZipFile capFile = new ZipFile( capPath );
			final Enumeration<? extends ZipEntry> capFileEntries = capFile.entries();

			while( capFileEntries.hasMoreElements() )
			{
				ZipEntry currentEntry = capFileEntries.nextElement();
				String entryPath = currentEntry.getName();

				// получаем имя файла
				int offset = entryPath.lastIndexOf( "/" );
				String entryName = entryPath.substring( offset + 1 );

				// проверяем - является ли данный файл одним из компонентов, запоминаем его номер
				boolean isComponent = false;
				int componentNumber;
				for( componentNumber = 1; componentNumber < COMP_FILES.length; ++componentNumber )
				{
					if( entryName.equals( COMP_FILES[ componentNumber ] ) )
					{
						isComponent = true;
						break;
					}
				}
				// если нет - не учитываем этот файл и переходим к следующему
				if( !isComponent )
				{
					continue;
				}

				InputStream entryStream = capFile.getInputStream( currentEntry );

				byte[] temp = new byte[ 64 ];
				Binary componentData = Bin();
				int t;
				while( (t = entryStream.read( temp )) != -1 )
				{
					componentData.add( t == 64 ? temp : Arrays.copyOfRange( temp, 0, t ) );
				}
				entryStream.close();

				// добавляем данные компонента в соответствующее место
				components.set( componentNumber, componentData );
			}

			capFile.close();
		}
		catch( IOException exp )
		{
			THROW( "Ошибка открытия cap-файла: \'" + capPath + "\'" );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void initAIDs()
	{
		classAIDs.clear();

		// получаем packageAID
		Binary header = components.get( COMPONENT_HEADER );
		MUST( header != null, "Отсутствует файл Header.cap" );
		MUST( header.slice( 1, 2 ).asU16() == (header.size() - 3), "Некорректный размер компонента Header.cap" );
		int aidLen = header.get( 12 );
		packageAID = header.slice( 13, aidLen );

		// получаем classAIDs
		Binary applet = components.get( COMPONENT_APPLET );
		if( (applet != null) && !applet.empty() )
		{
			MUST( applet.slice( 1, 2 ).asU16() == (applet.size() - 3), "Некорректный размер компонента Applet.cap" );
			int classCount = applet.get( 3 );

			for( int beg = 4; beg <= (applet.size() - 1) && classCount != 0; )
			{
				aidLen = applet.get( beg ) ;
				classAIDs.add( applet.slice( beg + 1, aidLen ) );
				beg += 3 + aidLen ;
			}
		}

		MUST( components.size() >= 9, "В пакете менее 9 компонентов" );
	}

}
