// Denom.org
// Author:  Sergey Karpov
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.testrunner;

import java.util.*;
import java.util.function.*;
import java.lang.reflect.*;

import org.denom.*;
import org.denom.log.*;

import static org.denom.Ex.*;

/**
 * Запуск наборов тестов (см. TestSuite).
 */
public final class TestRunner
{
	/**
	 * Список зарегистрированных сьютов.
	 */
	private Arr<TestSuite> suites = new Arr<TestSuite>();

	/**
	 * Список исключенных тестов.
	 */
	private Arr<String> excluded = new Arr<String>();

	private ILog log;

	/**
	 * Количество зарегистрированных сьютов.
	 */
	public int suitesRegistered;

	/**
	 * Количество зарегистрированных кейзов.
	 */
	public int casesRegistered;
	
	/**
	 * Количество исключенных кейзов (если кейз был одновременно в списке на запуск и в списке исключенных кейзов)
	 */
	public int casesExcluded;

	/**
	 * Количество кейзов, завершившихся успешно.
	 */
	public int casesOK;

	/**
	 * Количество кейзов, завершившихся с ошибкой.
	 */
	public int casesFailed;

	/**
	 * Количество начальных состояний, завершившихся с ошибкой.
	 */
	public int initStateFailed;

	/**
	 * Количество финалайзеров, завершившихся с ошибкой.
	 */
	public int finalizerFailed;
	
	// -----------------------------------------------------------------------------------------------------------------
	public TestRunner(){}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать лог для вывода сообщений о запуске тестов.
	 */
	public TestRunner setLog( ILog log )
	{
		this.log = log;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зарегистрировать тестовый сьют. Если добавляемый сьют уже зарегистрирован - исключение.
	 * @param suite
	 */
	public void registerSuite( final TestSuite suite )
	{
		for( TestSuite curSuite : suites )
		{
			String nameCurSuite = curSuite.getClass().getName();
			String nameAddedSuite = suite.getClass().getName();
			MUST( !nameCurSuite.equals( nameAddedSuite ), "Suite " + nameCurSuite + " already included" );
		}

		suites.add( suite );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Список зарегистрированных сьютов, копия внутреннего массива.
	 */
	public Arr<TestSuite> getSuites()
	{
		return new Arr<TestSuite>( suites );
	}

	//-----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает список кейзов в заданном сьюте - список методов (без наследуемых) объекта suite, начинающихся со слова "case".
	 */
	public static Arr<Method> getSuiteCases( final TestSuite suite )
	{
		Arr<Method> list = new Arr<Method>();
		for( Method curMethod : suite.getClass().getDeclaredMethods() )
		{
			if( curMethod.getName().startsWith( "case" ) )
			{
				list.add( curMethod );
			}
		}

		list.sort( (m1, m2) -> m1.getName().compareToIgnoreCase( m2.getName() ) );
		return list;
	}
	
	//-----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить к описанию тест-кейза (Цель, Методика) HTML-теги.
	 * Используется для корректного отображения многострочных описаний в GUI (tooltip).
	 * Требование:
	 *  - все строки должны заканчиваться символом '\n'
	 */
	public static String wrapTestCaseDecription( String desc )
	{
		String res = desc
		.replaceAll( "\\n", "<br>" )
		.replaceAll( "\\s{4}?", "<i>&nbsp;</i><i>&nbsp;</i><i>&nbsp;</i>" )
		.replace( "Цель:", "<b>Цель:</b>" )
		.replace( "Методика:", "<b>Методика:</b>" );
		return "<html>" + res + "</html>";
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Исключить из списка тестов подмножество тестов (семейства, сьюта или кейза).
	 * @param TestName - имя подмножества тестов, которые необходимо исключить.
	 */
	public void exclude( String TestName )
	{
		MUST( !TestName.isEmpty(), "The name test can't be empty" );
		excluded.add( TestName );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает список кейзов для запуска.
	 * @param curSuite - сьют.
	 * @param testName - имя подмножества тестов (семейства, сьюта или кейза).
	 * @return список кейзов, которые содержатся в сьюте, имя которых начинается на testName и которых нет в exclude-листе.
	 */
	private Arr<Method> getCasesToRun( final TestSuite curSuite, String testName )
	{
		Arr<Method> result = new Arr<Method>();
		Arr<Method> cases = getSuiteCases( curSuite );
		casesRegistered += cases.size();

		for( Method testCase : cases )
		{
			// Имя метода не совпадает с требуемым.
			String fullMethodName = curSuite.getClass().getName() + "." + testCase.getName() + ".";
			if( (testName.length() != 0) && (!fullMethodName.startsWith( testName + "." ) ) )
			{
				continue;
			}

			// Метод исключен.
			boolean exclude = false;
			for( String s : excluded )
			{
				if( fullMethodName.startsWith( s + "." ) )
				{
					exclude = true;
					++casesExcluded;
					break;
				}
			}

			if( !exclude )
			{
				result.add( testCase );
			}
		}
		return result;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызов initState сьюта.
	 * @param curSuite - сьют.
	 * @return - true, если initState выполнилось без исключения, иначе false.
	 */
	private boolean runInitState( final TestSuite curSuite )
	{
		log.writeln( Colors.WHITE, curSuite.getClass().getName() + ".initState:" );

		try
		{
			Ticker t = new Ticker();
			curSuite.initState();
			log.writeln( Colors.GREEN, " Ok, " + t.getDiffMs() + " ms\n" );
			return true;
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.RED_I, "    Error: " + getErrorDescription( ex ) );
		}

		++initStateFailed;
		return false;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызов finalizer сьюта.
	 * @param curSuite - сьют.
	 * @return - true, если finalizer выполнилось без исключения, иначе false.
	 */
	private boolean runFinalizer( final TestSuite curSuite )
	{
		log.writeln( Colors.WHITE, curSuite.getClass().getName() + ".finalizer:" );

		try
		{
			Ticker t = new Ticker();
			curSuite.finalizer();
			log.writeln( Colors.GREEN, " Ok, " + t.getDiffMs() + " ms\n\n" );
			return true;
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.RED_I, "    Error: " + getErrorDescription( ex ) );
		}

		++finalizerFailed;
		return false;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Запуск тестовых кейзов сьюта.
	 * @param curSuite - сьют.
	 * @param curMethod - итератор на массив кейзов сьюта.
	 * @param onCaseEnd - выполняетя в конце каждого кейза и возвращает его имя и результат.
	 */
	private void runTestCases( final TestSuite curSuite, Iterator<Method> curMethod, BiConsumer<String, Boolean> onCaseEnd )
	{
		String fullMethodName = "";
		try
		{
			int caseCounter = 1;
			while( curMethod.hasNext() )
			{
				Method method = curMethod.next();
				fullMethodName = curSuite.getClass().getName() + "." + method.getName();

				log.writeln( Colors.WHITE, "    " + caseCounter + ". " + fullMethodName + ":" );
				++caseCounter;

				Ticker t = new Ticker();
				method.invoke( curSuite );
				log.writeln( Colors.GREEN_I, "     Ok, " + t.getDiffMs() + " ms\n" );
				++casesOK;

				if( onCaseEnd != null ) onCaseEnd.accept( fullMethodName, true );
			}
		}
		catch( InvocationTargetException ex )
		{
			++casesFailed;
			log.writeln( Colors.RED_I, "    Error: " + getErrorDescription( ex.getCause() ) );
			if( onCaseEnd != null ) onCaseEnd.accept( fullMethodName, false );
		}
		catch( Throwable ex )
		{
			++casesFailed;
			log.writeln( Colors.RED_I, "    Error: " + getErrorDescription( ex ) );
			if( onCaseEnd != null ) onCaseEnd.accept( fullMethodName, false );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Очистка информации о процессе выполнения тестов.
	 */
	private void clearStats()
	{
		suitesRegistered = 0;

		casesRegistered = 0;
		casesExcluded = 0;
		casesOK = 0;
		casesFailed = 0;

		initStateFailed = 0;
		finalizerFailed = 0;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Запуск тестов.
	 * @param testName - имя подмножества тестов (семейства, сьюта или кейза). Если параметр пуст - запускать все 
	 *        имеющиеся тесты.
	 * @param onCaseEnd - выполняется в конце каждого кейза и возвращает его имя и результат.
	 */
	public long runTests( String testName, BiConsumer<String, Boolean> onCaseEnd )
	{
		clearStats();
		suitesRegistered = suites.size();

		Ticker t = new Ticker();
		for( TestSuite curSuite : suites )
		{
			Arr<Method> list = getCasesToRun( curSuite, testName );
			if( list.size() == 0)
			{
				continue;
			}

			Iterator<Method> cur = list.iterator();
			do
			{
				if( !runInitState( curSuite ) )
				{
					break;
				}

				runTestCases( curSuite, cur, onCaseEnd );
				runFinalizer( curSuite );
			}
			while( cur.hasNext() );
		}
		return t.getDiffMs();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Удобство: в конце каждого кейза ничего не вызывать.
	 */
	public long runTests( String testName )
	{
		return runTests( testName, null );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вывести результат выполнения тестов в лог.
	 */
	public void printTestResults()
	{
		log.writeln( Colors.WHITE, "======  Tests statistic  ======" );
		log.writeln( Colors.WHITE, "  All suites           : " + suitesRegistered );
		log.writeln( Colors.WHITE, "  All cases            : " + casesRegistered );
		log.writeln( Colors.WHITE, "  Excluded cases       : " + casesExcluded );
		log.writeln( Colors.WHITE, "  OK cases             : " + casesOK );

		if( (casesFailed != 0) || (initStateFailed != 0) || (finalizerFailed != 0) )
		{
			log.writeln( Colors.ERROR, "  =============================" );
			log.writeln( Colors.ERROR, "  Failed initStates: " + initStateFailed );
			log.writeln( Colors.ERROR, "  Failed cases     : " + casesFailed );
			log.writeln( Colors.ERROR, "  Failed finalizers: " + finalizerFailed );
		}
		else
		{
			log.writeln( Colors.GREEN_I, Strings.ln + "  No errors" + Strings.ln );
		}
		log.writeln( Colors.WHITE, "===============================" );
	}
}
