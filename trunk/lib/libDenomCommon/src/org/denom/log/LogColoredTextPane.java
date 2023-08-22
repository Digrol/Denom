// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.log;

import java.awt.Color;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.text.*;

import org.denom.*;
import org.denom.swing.SwingUtils;

import static org.denom.Ex.*;

/**
 * JTextPane для логирования.
 */
public class LogColoredTextPane extends JTextPane implements ILog
{
	private final static String FONT_NAME = SwingUtils.DEFAULT_FONT.getName();
	private final static int FONT_SIZE = SwingUtils.DEFAULT_FONT.getSize();

	/**
	 * Количество выводимых строк, после которых ожидаем прорисовки экрана
	 */
	private final static int STRINGS_TO_REPAINT = 100;

	/**
	 * Максимально возможное количество символов выводимого текста
	 */
	private int maxTextCapacity;

	/**
	 * По сколько символов удалять после превышения максимального кол-ва
	 */
	private int capacityToRemove;

	// -----------------------------------------------------------------------------------------------------------------
	private ILog nextLog;
	private Color defaultTextColor;

	private Document document;
	private DefaultCaret caret;

	/**
	 * Флаг - нужно ли сделать скролл
	 */
	private volatile boolean scrollReady;

	/**
	 * Счетчик строк до перерисовки
	 */
	private volatile int counterStrings;

	private boolean isGUIApp;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param isGUIApp - true для графических приложений, false - для скриптов.
	 */
	public LogColoredTextPane( boolean isGUIApp )
	{
		this( Colors.BLACK, Colors.WHITE, isGUIApp );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param isGUIApp - нужно задавать true для графических приложений, false - для скриптов.
	 */
	public LogColoredTextPane( int backgroundColor, int defaultTextColor, boolean isGUIApp )
	{
		super();
		this.isGUIApp = isGUIApp;

		setDefaultColor( defaultTextColor );
		setMaxTextCapacity( 1000000 );

		setBackground( new Color( backgroundColor, true ) );
		setEditable( false );

		// Документ области вывода
		document = new DefaultStyledDocument();
		setDocument( document );

		// Каретка области вывода
		caret = new DefaultCaret();
		caret.setVisible( false );
		caret.setUpdatePolicy( DefaultCaret.NEVER_UPDATE );

		setCaret( caret );
		startCaretThread();

		// Диалог копирования
		addMouseListener( new MouseAdapter()
		{
			@Override
			public void mouseReleased( final MouseEvent e )
			{
				if( e.isPopupTrigger() )
				{
					JPopupMenu menu = new JPopupMenu();
					JMenuItem itemCopy = new JMenuItem( "Копировать" );
					itemCopy.addActionListener( new DefaultEditorKit.CopyAction() );
					itemCopy.setEnabled( getSelectionStart() != getSelectionEnd() );
					menu.add( itemCopy );
					menu.show( e.getComponent(), e.getX(), e.getY() );
				}
			}
		} );

	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать максимальное кол-во символов в компоненте. При превышении объёма, наиболее старые символы будут удаляться
	 * @param textCapacity
	 */
	public void setMaxTextCapacity( int textCapacity )
	{
		MUST( textCapacity > 0, "Text capacity must be > 0" );
		this.maxTextCapacity = textCapacity;
		this.capacityToRemove = textCapacity / 8 + 1;
	}

	// -----------------------------------------------------------------------------------------------------------------
	// Поток для прокрутки текстового поля вниз.
	public void startCaretThread()
	{
		final Runnable scrollRunnable = new Runnable()
		{
			@Override
			public void run()
			{
				caret.setDot( maxTextCapacity );
			}
		};

		Thread caretThread = new Thread( new Runnable()
		{
			@Override
			public void run()
			{
				while( true )
				{
					try
					{
						Thread.sleep( 100 );
					}
					catch( InterruptedException ignored )
					{
						THROW( "InterruptedException" );
					}

					// одна прокрутка каретки
					if( scrollReady )
					{
						SwingUtilities.invokeLater( scrollRunnable );
						scrollReady = false;
					}
				}
			}
		} );

		caretThread.setName( "LogColoredTextPane Scroll" );
		caretThread.setDaemon( true );
		caretThread.start();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void writeDocument( final Color color, final String text )
	{
		Runnable writeStrRunnable = new Runnable()
		{
			@Override
			public void run()
			{
				++counterStrings;
				
				try
				{
					// Удаление старых строк, для ускорения работы компонента JTextPane
					if( document.getLength() > maxTextCapacity )
					{
						document.remove( 0, capacityToRemove );
					}
	
					// Добавление новых строк с выбранными аттрибутами
					MutableAttributeSet attr = new SimpleAttributeSet();
					StyleConstants.setFontFamily( attr, FONT_NAME );
					StyleConstants.setFontSize( attr, FONT_SIZE );
					StyleConstants.setForeground( attr, color );
					document.insertString( document.getLength(), text, attr );
					scrollReady = true;
				}
				catch( BadLocationException e )
				{
					THROW( e );
				}
			}
		};

		if( isGUIApp )
		{
			SwingUtilities.invokeLater( writeStrRunnable );
			return;
		}

		if( counterStrings < STRINGS_TO_REPAINT )
		{
			// Обычное добавление в EDT-очередь
			SwingUtilities.invokeLater( writeStrRunnable );
		}
		else
		{
			try
			{
				// Добавление в EDT-очередь с ожиданием завершения всех действий с целью отрисовки экрана
				SwingUtilities.invokeAndWait( writeStrRunnable );
				counterStrings = 0;
			}
			catch( Throwable e )
			{
				THROW( e );
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void write( String text )
	{
		writeDocument( defaultTextColor, text );
		if( nextLog != null )
		{
			nextLog.write( text );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void write( int color, String text )
	{
		writeDocument( new Color( color, true ), text );
		if( nextLog != null )
		{
			nextLog.write( color, text );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void writeln( String text )
	{
		write( text + Strings.ln );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void writeln( int color, String text )
	{
		write( color, text + Strings.ln );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void setDefaultColor( int color )
	{
		defaultTextColor = new Color( color, true );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public ILog setNext( ILog log )
	{
		nextLog = log;
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void close() {}

	private static final long serialVersionUID = 1L;
}
