// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.swing;

import java.awt.*;
import java.awt.event.*;

import javax.swing.JFrame;

/**
 * Меню свернуть-восстановить-закрыть для TrayMinimize
 */
public class TrayBasicPopup extends PopupMenu
{
	private MenuItem itemToFront;
	private MenuItem itemMinimize;
	private MenuItem itemExit;

	//------------------------------------------------------------------------------------------------------------------
	public TrayBasicPopup( JFrame frame, final TrayMinimize trayMinimize, final ActionListener onCloseListener )
	{
		super();

		itemToFront = new MenuItem( "Восстановить" );
		itemMinimize = new MenuItem( "Свернуть" );
		itemExit = new MenuItem( "Выйти" );

		add( itemToFront );
		add( itemMinimize );
		addSeparator();
		add( itemExit );

		itemToFront.addActionListener( e -> trayMinimize.setFrameOnFront() );
		itemMinimize.addActionListener( e -> trayMinimize.setFrameMinimized() );
		itemExit.addActionListener( e -> onCloseListener.actionPerformed( e ) );

		setMenuStateOnFront();

		frame.addWindowListener( new WindowAdapter()
		{
			@Override
			public void windowIconified( WindowEvent e )
			{
				setMenuStateMinimized();
			}

			@Override
			public void windowDeiconified( WindowEvent e )
			{
				setMenuStateOnFront();
			}
		} );
	}

	//------------------------------------------------------------------------------------------------------------------
	private void setMenuStateMinimized()
	{
		remove( itemMinimize );
		insert( itemToFront, 0 );
	}

	//------------------------------------------------------------------------------------------------------------------
	private void setMenuStateOnFront()
	{
		remove( itemToFront );
		insert( itemMinimize, 0 );
	}

	private static final long serialVersionUID = 1L;
}
