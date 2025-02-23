// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.terminal.kernel8;

import java.util.concurrent.*;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import javax.swing.*;
import javax.swing.event.*;

import org.denom.format.JSONObject;
import org.denom.log.*;
import org.denom.smartcard.*;
import org.denom.swing.*;

/**
 * GUI-tool - Emulation of POS-terminal. Performs a card transaction with the Kernel-8.
 */
@SuppressWarnings("serial")
public class TerminalKernel8GUI extends JFrame
{
	final int COLOR_MSG   = Colors.GREEN_I;

	private static final String HEADER          = "Terminal Kernel8";
	private static final String BUILD_VERSION   = "1.2025.02.19";
	private static final String COPYRIGHT       = "Denom.org. Version " + BUILD_VERSION;
	private static final String CONFIG_FILENAME = "TerminalKernel8.config";
	private static final String LOG_FILENAME    = "TerminalKernel8.log";

	private PanelTransaction panelTransaction;
	private PanelReader panelReader;

	private JTabbedPane tabbedPane;

	final LogColoredTextPane log;

	private JMenu menuReaderName;

	private ThreadPoolExecutor scriptExecutor = (ThreadPoolExecutor)Executors.newFixedThreadPool( 1 );

	CardReader cr;

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		EventQueue.invokeLater( () -> new TerminalKernel8GUI().setVisible( true ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private TerminalKernel8GUI()
	{
		super( HEADER );
		SwingUtils.setNimbusStyle( this );
		// SwingUtils.setIcon( this, "logo.png" );

		setBounds( 25, 25, 1000, 700 );
		setMinimumSize( new Dimension( 300, 300 ) );
		initMenu();

		log = new LogColoredTextPane( true );
		log.setDefaultColor( Colors.GREEN );
		log.setNext( new LogFile( LOG_FILENAME, true ) );

		panelTransaction = new PanelTransaction( this );
		panelReader = new PanelReader( this );

		tabbedPane = new JTabbedPane();
		tabbedPane.setBorder( BorderFactory.createEmptyBorder( 0, 0, 0, 0 ) );
		tabbedPane.setMinimumSize( new Dimension( 200, 200 ) );
		tabbedPane.setTabPlacement( JTabbedPane.LEFT );

		tabbedPane.addTab( "Perform transaction",    SwingUtils.createScrollPane( panelTransaction ) );
		tabbedPane.addTab( "Reader",         SwingUtils.createScrollPane( panelReader ) );

		tabbedPane.addChangeListener( this::onChangePage );

		JScrollPane scrollPaneLog = SwingUtils.createScrollPane( log );
		scrollPaneLog.setMinimumSize( new Dimension( 0, 50 ) );

		JSplitPane aSplitPane_TopBottom = new JSplitPane( JSplitPane.VERTICAL_SPLIT, tabbedPane, scrollPaneLog );
		aSplitPane_TopBottom.setBorder( BorderFactory.createEmptyBorder( 0, 0, 0, 0 ) );
		aSplitPane_TopBottom.setDividerSize( 5 );
		setContentPane( aSplitPane_TopBottom );

		addWindowListener( new WindowAdapter() { public void windowClosing( WindowEvent we )
		{
			onCloseWindow();
		} } );

		loadConfig();

		showReaderName();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void initMenu()
	{
		JMenu menuCopyright = new JMenu( COPYRIGHT );
		menuCopyright.setEnabled( false );
		menuReaderName = new JMenu( "" );
		menuReaderName.setForeground( new Color( 50, 50, 155 ) );
		menuReaderName.setEnabled( false );

		JMenuBar menuBar = new JMenuBar();
		menuBar.add( menuReaderName );
		menuBar.add( Box.createHorizontalGlue() );

		menuBar.add( menuCopyright );
		setJMenuBar( menuBar );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void onCloseWindow()
	{
		try
		{
			saveConfig();
			scriptExecutor.shutdownNow();
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.RED_I, ex.toString() );
		}
		System.exit( 0 );
	}

	private boolean readerPanelWasSelected = false;
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Refresh reader name in menu when switching panels.
	 */
	private void onChangePage( ChangeEvent event ) 
	{
		if( tabbedPane.getTitleAt( tabbedPane.getSelectedIndex() ).equals( "Reader" ) )
		{
			// 'Reader' panel choosen
			readerPanelWasSelected = true;
		}
		else if( readerPanelWasSelected )
		{
			// another panel
			readerPanelWasSelected = false;
			showReaderName();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private CardReaderOptions getReaderOptions()
	{
		return panelReader.panelSelectReader.toOpt();
	}

	// -----------------------------------------------------------------------------------------------------------------
	void writeDelimiter()
	{
		log.writeln( Colors.GRAY, "--------------------------------------------------------------------------------");
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Only one script can run at a time.
	 * @param script - Runnable или CardScript
	 */
	void runScript( String description, Runnable script )
	{
		if( scriptExecutor.getActiveCount() > 0 )
		{
			JOptionPane.showMessageDialog( getContentPane(), "Please, wait previous operation.",
					"Warning", JOptionPane.INFORMATION_MESSAGE );
			return;
		}

		scriptExecutor.execute( () -> 
		{
			log.writeln( Colors.GREEN_I, description );

			try( CardReader cr = ReaderFactory.create( getReaderOptions(), false ) )
			{
				this.cr = cr;
				boolean isApduLog = panelReader.checkBoxApduLog.isSelected();
				cr.setApduLogger( new ApduLoggerParsed( isApduLog ? log : new LogDummy() ) );
				cr.powerOn();

				script.run();

				cr.powerOff();

				log.writeln( Colors.GREEN_I, "Ok" );
			}
			catch( Throwable ex )
			{
				log.writeln( Colors.RED_I, "Error: " + ex.toString() );
			}
			cr = null;

			writeDelimiter();
		} );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Show reader name in menu
	 */
	private void showReaderName()
	{
		CardReaderOptions opt = getReaderOptions();
		menuReaderName.setText( opt.type + ": " + opt.getName() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Load program options from config-file.
	 */
	private void loadConfig()
	{
		try
		{
			if( !new File( CONFIG_FILENAME ).exists() )
				return;

			JSONObject jo = new JSONObject().load( CONFIG_FILENAME );

			CardReaderOptions crOpt = new CardReaderOptions().fromJSON( jo.getJSONObject( "Reader" ) );
			panelReader.panelSelectReader.fromOpt( crOpt );

			panelReader.checkBoxApduLog.setSelected( jo.getBoolean( "APDU Log Enabled" ) );

			panelTransaction.fromJSON( jo.getJSONObject( "Panel Transaction" ) );

			SwingContainerParams.fromJSON( this, jo.getJSONObject( "Main Frame" ) );
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.RED_I, ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Save program options to config-file.
	 */
	private void saveConfig()
	{
		try
		{
			JSONObject jo = new JSONObject();

			jo.put( "Reader", getReaderOptions().toJSON() );
			jo.put( "APDU Log Enabled", panelReader.checkBoxApduLog.isSelected() );

			jo.put( "Panel Transaction", panelTransaction.toJSON() );
			jo.put( "Main Frame", SwingContainerParams.toJSON( this ) );

			jo.save( CONFIG_FILENAME, 4 );
		}
		catch( Throwable ex )
		{
			log.writeln( Colors.RED_I, ex.toString() );
		}
	}

}
