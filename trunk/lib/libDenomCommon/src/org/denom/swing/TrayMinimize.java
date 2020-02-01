// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.swing;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

/**
 * Иконка для трея с обработкой сворачивания/разворачивания окна.<br>
 * Если трей не поддерживается/недоступен - ошибки не будет, но сворачивание в трей не произойдёт.
 */
public class TrayMinimize
{
	private JFrame frame;
	private TrayIcon trayIcon;

	private volatile boolean minimizeToTray = true;

	private long lastDeactivated;

	//------------------------------------------------------------------------------------------------------------------
	public TrayMinimize( Image image )
	{
		try
		{
			trayIcon = new TrayIcon( image );
			trayIcon.setImageAutoSize( true );
			SystemTray.getSystemTray().add( trayIcon );
	
			trayIcon.addMouseListener( new MouseAdapter()
			{
				@Override
				public void mouseClicked( MouseEvent e )
				{
					if( SwingUtilities.isLeftMouseButton( e ) )
					{
						onMouseLeftClicked();
					}
				}
			} );
		}
		catch( Throwable ex )
		{
			// создать иконку трея по какой-либо причине в системе невозможно 
		}
	}

	//------------------------------------------------------------------------------------------------------------------
	/**
	 * Сворачивать ли окно при нажатии левой кнопки мыши. Состояние по умолчанию - true
	 */
	public TrayMinimize setMinimizeToTray( boolean minimizeToTray )
	{
		this.minimizeToTray = minimizeToTray;

		return this;
	}

	//------------------------------------------------------------------------------------------------------------------
	/** Свернуть родительское окно */
	public void setFrameMinimized()
	{
		if( (frame == null) || (trayIcon == null) )
		{
			return;
		}

		frame.setState( JFrame.ICONIFIED );
		if( minimizeToTray )
		{
			frame.setVisible( false );
		}
	}

	//------------------------------------------------------------------------------------------------------------------
	/** Развернуть родительское окно */
	public void setFrameOnFront()
	{
		if( (frame == null) || (trayIcon == null) )
		{
			return;
		}

		frame.setVisible( true ); // !!! Важно чтобы сначала было setVisible
		frame.setState( JFrame.NORMAL );
		frame.toFront();
	}

	//------------------------------------------------------------------------------------------------------------------
	// Проверка, было ли окно активно до нажатия иконки трея
	public boolean wasFrameActiveRecently()
	{
		return (System.currentTimeMillis() - lastDeactivated) < 300;
	}

	//------------------------------------------------------------------------------------------------------------------
	private void onMouseLeftClicked()
	{
		if( frame == null )
		{
			return;
		}

		if( (frame.getState() == JFrame.NORMAL) && wasFrameActiveRecently() )
		{
			setFrameMinimized();
		}
		else
		{
			setFrameOnFront();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать окно, которое будет сворачиваться-разворачиваться по щелчку на иконке трей
	 */
	public TrayMinimize setParentFrame( JFrame frame )
	{
		this.frame = frame;
		
		if( frame == null )
		{
			return this;
		}

		frame.addWindowListener( new WindowAdapter()
		{
			@Override
			public void windowIconified( WindowEvent e )
			{
				setFrameMinimized();
			}

			@Override
			public void windowDeactivated( WindowEvent e )
			{
				lastDeactivated = System.currentTimeMillis();
			}
		} );

		setMinimizeToTray( true );

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать меню иконки трея по правой кнопке
	 */
	public TrayMinimize setTrayIconPopupMenu( PopupMenu popupMenu )
	{
		if( trayIcon != null )
			trayIcon.setPopupMenu( popupMenu );
		
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать изображение иконки трея
	 */
	public TrayMinimize setTrayIconImage( Image image )
	{
		if( trayIcon != null )
			trayIcon.setImage( image );
		
		return this;
	}

	//------------------------------------------------------------------------------------------------------------------
	/**
	 * Задать всплывающую подсказку при наведении мыши на иконку трея
	 */
	public TrayMinimize setTrayIconToolTip( String tooltip )
	{
		if( trayIcon != null )
			trayIcon.setToolTip( tooltip );
		
		return this;
	}

}