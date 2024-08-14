// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import java.net.InetAddress;
import javax.swing.*;
import org.denom.swing.SwingUtils;

/** 
 * Panel for choosing card reader.
 */
public class PanelSelectReader extends JPanel
{
	public static final String VR_SERVER = "denom.org";
	public static final int    VR_DEFAULT_PORT = 4256;

	// -----------------------------------------------------------------------------------------------------------------
	private JRadioButton mRadio_PCSC;
	private JComboBox<String> mCombo_PCSC;
	private JButton mButton_PCSCRefresh;

	private JRadioButton mRadio_VR;

	private JLabel mLabel_VRName;
	private JComboBox<String> mCombo_VR;

	private JLabel mLabel_VRHost;
	private JTextField mText_VRHost;
	private JButton mButton_GetVRList;

	private JLabel mLabel_VRClientName;
	private JTextField mText_VRClientName;
	
	private JLabel mLabel_VRPassword;
	private JTextField mText_VRPassword;

	// -----------------------------------------------------------------------------------------------------------------
	public PanelSelectReader()
	{
		this( new CardReaderOptions() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public PanelSelectReader( CardReaderOptions opt )
	{
		mRadio_PCSC = new JRadioButton( "PC/SC Reader" );
		mRadio_PCSC.addActionListener( e -> enableComponents( mCombo_PCSC ) );

		mCombo_PCSC = new JComboBox<String>();
		for( String reader : CardReaderPCSC.enumerateReaders() )
		{
			mCombo_PCSC.addItem( reader );
		}

		mButton_PCSCRefresh = new JButton( "Refresh" );
		mButton_PCSCRefresh.addActionListener( e -> onRefreshPCSC() );

		mRadio_VR = new JRadioButton( "Virtual Reader" );
		mRadio_VR.addActionListener( e -> enableComponents( mCombo_VR ) );

		mLabel_VRName = new JLabel( "Reader name" );
		mCombo_VR = new JComboBox<String>();
		mCombo_VR.setEditable( true );
		mButton_GetVRList = new JButton( "Get list" );
		mButton_GetVRList.addActionListener( e -> onGetVRList() );

		mLabel_VRHost = new JLabel( "Server address" );
		mText_VRHost = SwingUtils.CreateLimitedTextField( 128 );
		mText_VRHost.setToolTipText( "<html>Examples: <br>"
				+ "1) Default port:  <i>denom.org</i><br>"
				+ "2) <i>127.0.0.1</i><br>"
				+ "3) With port:  <i>some.domain.ru:5678</i></html>" );

		mLabel_VRClientName = new JLabel( "Client name" );
		mText_VRClientName = SwingUtils.CreateLimitedTextField( 128 );
		mText_VRClientName.setToolTipText( "How to introduce myself when connecting to the reader?" );
		mLabel_VRPassword = new JLabel( "Password" );
		mText_VRPassword = SwingUtils.CreateLimitedTextField( 128 );
		mText_VRPassword.setToolTipText( "Password to connect to the specified reader" );

		ButtonGroup radioGroup = new ButtonGroup();
		radioGroup.add( mRadio_PCSC );
		radioGroup.add( mRadio_VR );
		mRadio_PCSC.setSelected( true );


		int prefSize = GroupLayout.PREFERRED_SIZE;
		int compHeight = 30;
		GroupLayout group = new GroupLayout( this );
		group.setHorizontalGroup(
		group.createParallelGroup()
			.addComponent( mRadio_PCSC, prefSize, 182, prefSize )
			.addGroup( group.createSequentialGroup()
				.addGap( 28 )
				.addComponent( mCombo_PCSC, prefSize, 432, prefSize )
				.addComponent( mButton_PCSCRefresh, prefSize, 180, prefSize ) )

			.addComponent( mRadio_VR, prefSize, 190, prefSize )
			.addGroup( group.createSequentialGroup()
				.addGap( 30 )
				.addComponent( mLabel_VRHost, prefSize, 130, prefSize )
				.addComponent( mText_VRHost, prefSize, 300, prefSize ) )
			.addGroup( group.createSequentialGroup()
				.addGap( 54 )
				.addComponent( mLabel_VRName, prefSize, 106, prefSize )
				.addComponent( mCombo_VR, prefSize, 300, prefSize )
				.addComponent( mButton_GetVRList, prefSize, 180, prefSize ) )
			.addGroup( group.createSequentialGroup()
				.addGap( 75 )
				.addComponent( mLabel_VRPassword, prefSize, 85, prefSize )
				.addComponent( mText_VRPassword, prefSize, 160, prefSize ) )
			.addGroup( group.createSequentialGroup()
				.addGap( 55 )
				.addComponent( mLabel_VRClientName, prefSize, 105, prefSize )
				.addComponent( mText_VRClientName, prefSize, 160, prefSize ) )
		);

		group.setVerticalGroup(
		group.createSequentialGroup()
			.addComponent( mRadio_PCSC, prefSize, compHeight, prefSize )
			.addGroup( group.createParallelGroup()
				.addComponent( mCombo_PCSC, prefSize, compHeight, prefSize )
				.addComponent( mButton_PCSCRefresh, prefSize, compHeight, prefSize ) )
			.addGap( 10 )
			
			.addComponent( mRadio_VR, prefSize, compHeight, prefSize )
			.addGroup( group.createParallelGroup()
				.addComponent( mLabel_VRHost, prefSize, compHeight, prefSize )
				.addComponent( mText_VRHost, prefSize, compHeight, prefSize ) )
			.addGroup( group.createParallelGroup()
				.addComponent( mLabel_VRName, prefSize, compHeight, prefSize )
				.addComponent( mCombo_VR, prefSize, compHeight, prefSize )
				.addComponent( mButton_GetVRList, prefSize, compHeight, prefSize ) )
			.addGroup( group.createParallelGroup()
				.addComponent( mLabel_VRPassword, prefSize, compHeight, prefSize )
				.addComponent( mText_VRPassword, prefSize, compHeight, prefSize ) )
			.addGroup( group.createParallelGroup()
				.addComponent( mLabel_VRClientName, prefSize, compHeight, prefSize )
				.addComponent( mText_VRClientName, prefSize, compHeight, prefSize ) )
		);

		this.setLayout( group );
		fromOpt( opt );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static String getHostName()
	{
		try
		{
			return InetAddress.getLocalHost().getHostName();
		}
		catch( Throwable ex ){}
		return "";
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать состояние диалога согласно переменной opt.
	 */
	public void fromOpt( final CardReaderOptions opt )
	{
		mCombo_PCSC.setSelectedItem( opt.pcscName );

		mCombo_VR.setSelectedItem( opt.vrName );

		String host = opt.vrHost.trim();
		if( host.isEmpty() )
		{
			mText_VRHost.setText( VR_SERVER + ":" + String.valueOf( opt.vrPort ) );
		}
		else
		{
			mText_VRHost.setText( host + ":" + String.valueOf( opt.vrPort ) );
		}

		if( opt.vrClientName.isEmpty() )
		{
			mText_VRClientName.setText( getHostName() );
		}
		else
		{
			mText_VRClientName.setText( opt.vrClientName );
		}

		mText_VRPassword.setText( opt.vrPassword );

		switch( opt.type )
		{
			case ReaderType.PCSC:
			case ReaderType.UNKNOWN:
				mRadio_PCSC.setSelected( true );
				enableComponents( mCombo_PCSC );
				break;

			case ReaderType.VR:
				mRadio_VR.setSelected( true );
				enableComponents( mCombo_VR );
				break;

			default:
				break;
		}
		
	}

	// -----------------------------------------------------------------------------------------------------------------
	private String getHost()
	{
		return mText_VRHost.getText().split( ":" )[0];
	}

	// -----------------------------------------------------------------------------------------------------------------
	private int getPort()
	{
		String[] arr = mText_VRHost.getText().split( ":" );
		int port = VR_DEFAULT_PORT;
		if( arr.length > 1 )
		{
			try
			{
				port = Integer.parseInt( arr[1] );
			}
			catch( Throwable ex )
			{
				port = 0;
			}
		}
		return port;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выгрузить состояние диалога в переменную opt.
	 */
	public void toOpt( CardReaderOptions opt )
	{
		opt.pcscName = "";
		if( mCombo_PCSC.getSelectedItem() != null )
		{
			opt.pcscName = mCombo_PCSC.getSelectedItem().toString();
		}

		opt.vrName = mCombo_VR.getSelectedItem().toString();
		
		opt.vrHost = getHost();
		opt.vrPort = getPort();
		opt.vrClientName = mText_VRClientName.getText();
		opt.vrPassword = mText_VRPassword.getText();

		if( mRadio_PCSC.isSelected() )
		{
			opt.type = ReaderType.PCSC;
		}
		else if( mRadio_VR.isSelected() )
		{
			opt.type = ReaderType.VR;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выгрузить состояние диалога в переменную opt.
	 */
	public CardReaderOptions toOpt()
	{
		CardReaderOptions opt = new CardReaderOptions();
		toOpt( opt );
		return opt;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Активировать/деактивировать все элементы панели.
	 */
	public void setEnabledComponents( boolean enabled )
	{
		mRadio_PCSC.setEnabled( enabled );
		mRadio_VR.setEnabled( enabled );
		
		mCombo_PCSC.setEnabled( enabled );
		mButton_PCSCRefresh.setEnabled( enabled );

		mLabel_VRHost.setEnabled( enabled );
		mText_VRHost.setEnabled( enabled );

		mLabel_VRName.setEnabled( enabled );
		mCombo_VR.setEnabled( enabled );
		mButton_GetVRList.setEnabled( enabled );

		mLabel_VRClientName.setEnabled( enabled );
		mText_VRClientName.setEnabled( enabled );

		mLabel_VRPassword.setEnabled( enabled );
		mText_VRPassword.setEnabled( enabled );
		
		if( enabled )
		{
			if( mRadio_PCSC.isSelected() )
			{
				enableComponents( mCombo_PCSC );
			}
			else
			{
				enableComponents( mCombo_VR );
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void onRefreshPCSC()
	{
		Object currentSelected = mCombo_PCSC.getSelectedItem();
		String[] readers = CardReaderPCSC.enumerateReaders();
		mCombo_PCSC.removeAllItems();
		for( String reader : readers )
		{
			mCombo_PCSC.addItem( reader );
		}
		mCombo_PCSC.setSelectedItem( currentSelected );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void onGetVRList()
	{
		try( CardReaderVRSocket reader = new CardReaderVRSocket() )
		{
			reader.connectToVR( getHost(), getPort() );
			String[] readerNames = reader.enumReaders();
			mCombo_VR.removeAllItems();
			for( String readerName : readerNames )
			{
				mCombo_VR.addItem( readerName );
			}
		}
		catch( Throwable t )
		{
			SwingUtils.showMessage( this.getParent(), "Failed to get the list of readers", "Warning", JOptionPane.WARNING_MESSAGE );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void enableComponents( JComponent comp )
	{
		mCombo_PCSC.setEnabled( comp == mCombo_PCSC );
		mButton_PCSCRefresh.setEnabled( comp == mCombo_PCSC );

		boolean isVR = (comp == mCombo_VR);
		mLabel_VRHost.setEnabled( isVR );
		mText_VRHost.setEnabled( isVR );

		mLabel_VRName.setEnabled( isVR );
		mCombo_VR.setEnabled( isVR );
		mButton_GetVRList.setEnabled( isVR );

		mLabel_VRClientName.setEnabled( isVR );
		mText_VRClientName.setEnabled( isVR );

		mLabel_VRPassword.setEnabled( isVR );
		mText_VRPassword.setEnabled( isVR );

		comp.requestFocusInWindow();
	}

	private static final long serialVersionUID = 1L;
}