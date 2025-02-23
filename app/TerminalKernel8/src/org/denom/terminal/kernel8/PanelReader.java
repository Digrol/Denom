// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.terminal.kernel8;

import javax.swing.*;

import org.denom.log.*;
import org.denom.smartcard.*;

/**
 * Панель настроек ридера.
 */
@SuppressWarnings("serial")
class PanelReader extends JPanel
{
	PanelSelectReader panelSelectReader;
	JCheckBox checkBoxApduLog;
	TerminalKernel8GUI main;

	// -----------------------------------------------------------------------------------------------------------------
	PanelReader( TerminalKernel8GUI main )
	{
		this.main = main;

		setBorder( BorderFactory.createEmptyBorder( 10, 10, 10, 10 ) );

		panelSelectReader = new PanelSelectReader();

		checkBoxApduLog = new JCheckBox( "Print APDUs" );
		checkBoxApduLog.setSelected( false );

		JButton buttonEnumReaders = new JButton( "List PC/SC-readers" );
		buttonEnumReaders.setToolTipText( "Print list of connected PC/SC-readers" );
		buttonEnumReaders.addActionListener( e -> onEnumReaders() );

		int prefSize = GroupLayout.PREFERRED_SIZE;
		int compHeight = 25;
		GroupLayout group = new GroupLayout( this );
		setLayout( group );

		group.setHorizontalGroup(
		group.createParallelGroup()
			.addComponent( panelSelectReader )
			.addComponent( checkBoxApduLog, prefSize, 300, prefSize )
			.addComponent( buttonEnumReaders, prefSize, 220, prefSize )
		);
		group.setVerticalGroup(
		group.createSequentialGroup()
			.addComponent( panelSelectReader )
			.addGap( 10 )
			.addComponent( checkBoxApduLog, prefSize, compHeight, prefSize )
			.addGap( 20 )
			.addComponent( buttonEnumReaders, prefSize, 40, prefSize )
		);
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	private void onEnumReaders()
	{
		main.log.writeln( main.COLOR_MSG, "Get list of PC/SC-readers..." );

		int count = 1;
		for( String name : CardReaderPCSC.enumerateReaders() )
		{
			main.log.writeln( Colors.GREEN, count++ + "  -  " + name );
		}

		main.log.writeln( main.COLOR_MSG, "Ok" );
		main.writeDelimiter();
	}
}
