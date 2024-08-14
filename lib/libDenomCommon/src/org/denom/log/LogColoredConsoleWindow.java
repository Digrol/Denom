// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.log;

import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

import javax.swing.*;

import org.denom.*;

import static org.denom.swing.SwingUtils.*;
import static org.denom.Ex.THROW;

/**
 * Лог - окно с текстом разного цвета.
 */
public class LogColoredConsoleWindow implements ILog
{
	private JTextField inputTextField;
	private String inputStr;

	private int defaultColor = Colors.WHITE;
	private ILog nextLog;

	// -----------------------------------------------------------------------------------------------------------------
	private final static int BACKGROUND_COLOR = 0xFF101010;

	// -----------------------------------------------------------------------------------------------------------------
	public JFrame consoleWindow;
	public LogColoredTextPane coloredTextPaneLog;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор по умолчанию.
	 */
	public LogColoredConsoleWindow()
	{
		this( "Console App" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор, размеры окна - по умолчанию, задаётся только заголовок окна.
	 * @param windowCaption - Текст в заголовке окна.
	 */
	public LogColoredConsoleWindow( String windowCaption )
	{
		this( 100, 20, 900, 768, windowCaption );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор.
	 * @param x - Координата левого верхнего угла по оси X относительно начала экрана.
	 * @param y - Координата левого верхнего угла по оси Y относительно начала экрана.
	 * @param width - Ширина окна.
	 * @param height - Высота окна.
	 * @param windowCaption - Текст в заголовке окна.
	 */
	public LogColoredConsoleWindow( int x, int y, int width, int height, String windowCaption )
	{
		consoleWindow = new JFrame( windowCaption );
		consoleWindow.setDefaultCloseOperation( JFrame.EXIT_ON_CLOSE );
		consoleWindow.setLocation( x, y );
		consoleWindow.setSize( width, height );
		consoleWindow.setResizable( true );

		coloredTextPaneLog = new LogColoredTextPane( BACKGROUND_COLOR, defaultColor, false );
		consoleWindow.getContentPane().add( new JScrollPane( coloredTextPaneLog ) );
		createInputField();
		consoleWindow.getContentPane().add( inputTextField, java.awt.BorderLayout.SOUTH );

		consoleWindow.setVisible( true );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void createInputField()
	{
		// Текстовая область ввода текста
		inputTextField = new JTextField();
		inputTextField.setFont( DEFAULT_FONT );
		inputTextField.addKeyListener( new KeyListener()
		{
			@Override
			public void keyPressed( KeyEvent e )
			{
				if( e.getKeyCode() == KeyEvent.VK_ENTER )
				{
					inputStr = inputTextField.getText();
					inputTextField.setText( "" );
				}
			}

			@Override
			public void keyTyped( KeyEvent e ) {}
			@Override
			public void keyReleased( KeyEvent e ) {}
		} );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public String readln()
	{
		inputTextField.grabFocus();
		String temp = inputStr;
		while( temp == inputStr )
		{
			try
			{
				Thread.sleep( 50 );
			}
			catch( InterruptedException ignored )
			{
				THROW( "InterruptedException" );
			}
		}
		return inputStr;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void write( String text )
	{
		coloredTextPaneLog.write( defaultColor, text );
		if( nextLog != null )
		{
			nextLog.write( text );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void write( int color, String text )
	{
		coloredTextPaneLog.write( color, text );
		if( nextLog != null )
		{
			nextLog.write( color, text );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void writeln( final String text )
	{
		write( text + Strings.ln );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void writeln( int color, final String text )
	{
		write( color, text + Strings.ln );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void setDefaultColor( int color )
	{
		defaultColor = color;
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
	public void close()
	{
		consoleWindow.setVisible( false );
		consoleWindow.dispose();
	}

}
