// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.swing;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.plaf.nimbus.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.*;
import javax.swing.undo.UndoManager;
import javax.swing.tree.*;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;

import static org.denom.Ex.*;

/**
 * Утилиты и компоненты для использования в Swing-приложениях.
 */
public class SwingUtils
{
	public static final Font DEFAULT_FONT = new Font( "Consolas", Font.PLAIN, 15 );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить действие (runnable) в потоке AWT и дождаться завершения обработки этого действия.
	 * Исключение, возникшее в runnable, будет выброшено из этого метода.
	 */
	public static void invokeAndWait( Runnable runnable )
	{
		try
		{
			EventQueue.invokeAndWait( runnable );
		}
		catch( InvocationTargetException ex )
		{
			THROW( ex.getCause().getMessage() );
		}
		catch( InterruptedException e )
		{}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выполнить действие (runnable) в потоке AWT.
	 */
	public static void invokeLater( Runnable runnable )
	{
		EventQueue.invokeLater( runnable );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать иконку для фрейма.
	 * @param fileName - Относительный путь к файлу с иконкой.
	 */
	public static void setIcon( JFrame frame, String fileName )
	{
		URL pathURL = frame.getClass().getClassLoader().getResource( fileName );
		frame.setIconImage( new ImageIcon( pathURL ).getImage() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Настроить стиль окна - Nimbus.
	 * @param frame - Фрейм, для которого задаётся стиль.
	 * @param defaultFont - Шрифт по умолчанию.
	 */
	public static void setNimbusStyle( JFrame frame )
	{
		setNimbusStyle( frame, DEFAULT_FONT );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Настроить стиль окна - Nimbus.
	 * @param frame - Фрейм, для которого задаётся стиль.
	 * @param defaultFont - Шрифт по умолчанию.
	 */
	public static void setNimbusStyle( JFrame frame, final Font defaultFont )
	{
		try
		{
			NimbusLookAndFeel nimbusLookAndFeel = new NimbusLookAndFeel();
			UIDefaults uiDefaults = nimbusLookAndFeel.getDefaults();
			uiDefaults.put( "defaultFont", defaultFont );
			uiDefaults.put( "TextPane[Enabled].backgroundPainter", new AbstractRegionPainter()
			{
				protected AbstractRegionPainter.PaintContext getPaintContext()
				{
					return new AbstractRegionPainter.PaintContext( null, null, false );
				}

				protected void doPaint( Graphics2D g, JComponent c, int width, int height, Object[] extendedCacheKeys )
				{}
			});
			uiDefaults.put( "TabbedPane:TabbedPaneTab[Disabled].backgroundPainter", new AbstractRegionPainter()
			{
				protected AbstractRegionPainter.PaintContext getPaintContext()
				{
					return new AbstractRegionPainter.PaintContext( null, null, false );
				}

				protected void doPaint( Graphics2D g, JComponent c, int width, int height, Object[] extendedCacheKeys )
				{}
			});

			UIManager.setLookAndFeel( nimbusLookAndFeel );

			UIManager.put( "InternalFrame.titleFont", defaultFont );
			
			UIManager.put( "TitledBorder.font", defaultFont );

			UIManager.put( "FileChooser.readOnly", Boolean.TRUE );
			UIManager.put( "FileChooser.saveButtonText", "Save" );
			UIManager.put( "FileChooser.openButtonText", "Open" );
			UIManager.put( "FileChooser.cancelButtonText", "Cancel" );

			UIManager.put( "FileChooser.lookInLabelText", "Directory:" );
			UIManager.put( "FileChooser.filesOfTypeLabelText", "File type:" );
			UIManager.put( "FileChooser.fileNameLabelText", "File name:" );

			UIManager.put( "OptionPane.yesButtonText", "OK" );
			UIManager.put( "OptionPane.cancelButtonText", "Cancel" );

			SwingUtilities.updateComponentTreeUI( frame );
		}
		catch( Throwable ex )
		{
			THROW( ex );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	// Текстовое поле с всплывающим меню копирования и ограничением ввода
	public static JTextField CreateLimitedTextField( int maxSize )
	{
		final JTextField textField = new JTextField();
		textField.addMouseListener( new MouseAdapter()
		{
			public void mouseReleased( final MouseEvent e )
			{
				if( e.isPopupTrigger() )
				{
					JPopupMenu menu = new JPopupMenu();
					JMenuItem itemCopy = new JMenuItem( "Copy" );
					JMenuItem itemPaste = new JMenuItem( "Paste" );
					itemCopy.addActionListener( new DefaultEditorKit.CopyAction() );
					itemPaste.addActionListener( new DefaultEditorKit.PasteAction() );
					itemCopy.setEnabled( textField.getSelectionStart() != textField.getSelectionEnd() );
					itemPaste.setEnabled( true );
					menu.add( itemCopy );
					menu.add( itemPaste );
					menu.show( e.getComponent(), e.getX(), e.getY() );
				}
			}
		} );

		textField.setDocument( createLimitedSizeDocument( maxSize ) );
		makeUndoable( textField );
		return textField;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	// Документ с ограничением по количеству вводимых символов
	public static Document createLimitedSizeDocument( final int max )
	{
		return new PlainDocument()
		{
			private static final long serialVersionUID = 1L;

			@Override
			public void insertString( int offs, String str, AttributeSet a ) throws BadLocationException
			{
				if( getLength() + str.length() > max )
				{
					str = str.substring( 0, max - getLength() );
				}
				super.insertString( offs, str, a );
			}
		};
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Модель таблицы без возможности редактирования ячеек.
	 */
	public static DefaultTableModel createTableModelReadOnly( Object[][] tableData, String[] header )
	{
		return new DefaultTableModel( tableData, header )
		{
			private static final long serialVersionUID = 1L;

			@Override
			public boolean isCellEditable( int row, int column )
			{
				return false;
			}
		};
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	// Таблица с выборочным выделением ячеек
	public static JTable createTableWithCopy()
	{
		final JTable table = new JTable()
		{
			private static final long serialVersionUID = 1L;

			@Override
			public String getToolTipText( MouseEvent e )
			{
				Point pt = e.getPoint();
				int row = rowAtPoint( pt );
				int column = columnAtPoint( pt );
				boolean check = (row < 0 ) || (column < 0);
				return check ? null : getValueAt( row, column ).toString();
			}
		};
		table.setRowSelectionAllowed( true );
		table.setColumnSelectionAllowed( true );

		// Диалог копирования
		table.addMouseListener( TableMouseListener( table ) );
		table.setAutoResizeMode( JTable.AUTO_RESIZE_OFF );
		return table;
	}

	// -----------------------------------------------------------------------------------------------------------------
	// Панель прокрутки с пустой границей
	public static JScrollPane createScrollPane( Component component )
	{
		JScrollPane scrollPane = new JScrollPane( component );
		scrollPane.setBorder( BorderFactory.createEmptyBorder() );
		return scrollPane;
	}

	// -----------------------------------------------------------------------------------------------------------------
	// Текстовая область с всплывающим меню копирования
	public static JTextArea createTextArea()
	{
		final JTextArea textArea = new JTextArea();
		((DefaultCaret)textArea.getCaret()).setUpdatePolicy( DefaultCaret.NEVER_UPDATE );

		// Диалог копирования
		textArea.addMouseListener( new MouseAdapter() { public void mouseReleased( final MouseEvent e )
		{
			if( e.isPopupTrigger() )
			{
				JPopupMenu menu = new JPopupMenu();
				JMenuItem itemCopy = new JMenuItem( "Copy" );
				itemCopy.addActionListener( new DefaultEditorKit.CopyAction() );
				itemCopy.setEnabled( textArea.getSelectionStart() != textArea.getSelectionEnd() );
				menu.add( itemCopy );
				menu.show( e.getComponent(), e.getX(), e.getY() );
			}
		} } );
		return textArea;
	}

	// -----------------------------------------------------------------------------------------------------------------
	// Обновить дерево с сохранением состояния
	public static void refreshTree( final JTree tree )
	{
		SwingUtilities.invokeLater( new Runnable() { public void run()
		{
			StringBuilder sb = new StringBuilder();
			// Сохранение открытых областей
			for( int i = 0; i < tree.getRowCount(); i++ )
			{
				TreePath path = tree.getPathForRow( i );
				if( tree.isExpanded( i ) )
				{
					sb.append( path.toString() );
					sb.append( "," );
				}
			}
			TreePath selectedPath = tree.getSelectionPath();

			((DefaultTreeModel)tree.getModel()).reload();

			// Загрузка открытых областей
			for( int i = 0; i < tree.getRowCount(); i++ )
			{
				TreePath path = tree.getPathForRow( i );
				if( sb.toString().contains( path.toString() ) )
				{
					tree.expandRow( i );
				}
			}
			tree.setSelectionPath( selectedPath );
		} } );
	}

	// -----------------------------------------------------------------------------------------------------------------
	// Обработчик всплывающего меню копирования
	public static MouseListener TableMouseListener( final JTable table )
	{
		return new MouseAdapter()
		{
			@Override
			public void mousePressed( final MouseEvent e )
			{
				showCopyMenu( e );
			}

			@Override
			public void mouseReleased( final MouseEvent e )
			{
				showCopyMenu( e );
			}

			private void showCopyMenu( final MouseEvent e )
			{
				if( !e.isPopupTrigger() )
				{
					return;
				}

				JPopupMenu menu = new JPopupMenu();
				JMenuItem itemCopy = new JMenuItem( "Copy" );

				menu.add( itemCopy );
				menu.show( e.getComponent(), e.getX(), e.getY() );

				int col = table.getSelectedColumn();
				int row = table.getSelectedRow();
				if( col == -1 || row == -1 )
				{
					return;
				}

				itemCopy.addActionListener( TableItemClickListener( table ) );
			}
		};
	}

	// -----------------------------------------------------------------------------------------------------------------
	// Обработчик копирования при нажатии элемента меню
	static ActionListener TableItemClickListener( final JTable table )
	{
		return new ActionListener()
		{
			@Override
			public void actionPerformed( ActionEvent e )
			{
				StringBuilder sb = new StringBuilder();
				for( int i = 0; i < table.getRowCount(); ++i )
				{
					for( int j = 0; j < table.getColumnCount(); ++j )
					{
						sb.append( table.isCellSelected( i, j ) ? table.getValueAt( i, j ) +"\t" : "" );
					}
					if( table.isRowSelected( i ) )
					{
						sb.deleteCharAt( sb.length() - 1 );
						sb.append( "\n" );
					}
				}
				StringSelection selection = new StringSelection( sb.toString() );
				Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
				clipboard.setContents( selection, selection );
			}
		};
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Добавить текстовому компоненту возможность отмены ввода
	 */
	@SuppressWarnings("serial")
	public static void makeUndoable( JTextComponent comp )
	{
		final UndoManager undoMgr = new UndoManager();

		final String UNDO = "Undo";
		final String REDO = "Redo";

		comp.getDocument().addUndoableEditListener( new UndoableEditListener()
		{
			public void undoableEditHappened( UndoableEditEvent e )
			{
				undoMgr.addEdit( e.getEdit() );
			}
		} );
		comp.getActionMap().put( UNDO, new AbstractAction( UNDO )
		{
			public void actionPerformed( ActionEvent evt )
			{
				if( undoMgr.canUndo() )
					undoMgr.undo();
			}
		} );
		comp.getActionMap().put( REDO, new AbstractAction( REDO )
		{
			public void actionPerformed( ActionEvent evt )
			{
				if( undoMgr.canRedo() )
					undoMgr.redo();
			}
		} );

		comp.getInputMap().put( KeyStroke.getKeyStroke( KeyEvent.VK_Y, InputEvent.CTRL_DOWN_MASK ), REDO );
		comp.getInputMap().put( KeyStroke.getKeyStroke( KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK ), UNDO );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void showMessage( final Component parentComponent, final String message,
		final String title, final int msgType )
	{
		SwingUtilities.invokeLater( new Runnable()
		{
			public void run()
			{
				JOptionPane.showMessageDialog( parentComponent, message, title, msgType );
			}
		} );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public static void showMessageError( final Component parentComponent, final String message )
	{
		showMessage( parentComponent, message, "Error", JOptionPane.ERROR_MESSAGE );
	}

}