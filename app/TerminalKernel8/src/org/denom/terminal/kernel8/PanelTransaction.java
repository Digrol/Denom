// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.terminal.kernel8;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.util.Random;

import javax.swing.*;

import org.denom.Binary;
import org.denom.Strings;
import org.denom.crypt.ec.ECAlg;
import org.denom.crypt.ec.Fp.custom.Secp256r1;
import org.denom.format.JSONObject;
import org.denom.smartcard.emv.TagEmv;
import org.denom.smartcard.emv.kernel8.TerminalK8;
import org.denom.swing.SwingUtils;

import static org.denom.Ex.*;
import static org.denom.Binary.Bin;

/**
 * Panel with transaction params.
 */
@SuppressWarnings("serial")
class PanelTransaction extends JPanel
{
	TerminalKernel8GUI main;

	JTextField textTrcAmount;
	JTextField textAID;

	// -----------------------------------------------------------------------------------------------------------------
	PanelTransaction( TerminalKernel8GUI main )
	{
		this.main = main;
		setBorder( BorderFactory.createEmptyBorder( 10, 10, 10, 10 ) );

		JLabel labelInfo = new JLabel( "<html>Performing transaction with card application.</html>" );
		Color labelColor = new Color( 50, 50, 155 );
		labelInfo.setForeground( labelColor );

		JLabel labelAID = new JLabel( "Application AID" );
		textAID = SwingUtils.CreateLimitedTextField( 50 );
		textAID.setToolTipText( "Hex, 5-16 bytes" );

		JLabel labelTrcAmount = new JLabel( "Amount" );
		textTrcAmount = SwingUtils.CreateLimitedTextField( 15 );
		textTrcAmount.setToolTipText( "Amount must be 'n 12' (up to 12 numbers)" );

		JButton buttonTransaction = new JButton( "Perform transaction" );
		buttonTransaction.addActionListener( this::onTransaction );

		int prefSize = GroupLayout.PREFERRED_SIZE;
		int compHeight = 30;
		GroupLayout layout = new GroupLayout( this );
		this.setLayout( layout );

		layout.setHorizontalGroup( layout.createParallelGroup()
			.addComponent( labelInfo )

			.addGroup( layout.createSequentialGroup()
				.addComponent( labelAID, prefSize, 150, prefSize )
				.addComponent( textAID, prefSize, 250, prefSize ) )

			.addGroup( layout.createSequentialGroup()
				.addComponent( labelTrcAmount, prefSize, 150, prefSize )
				.addComponent( textTrcAmount, prefSize, 250, prefSize ) )

			.addComponent( buttonTransaction, prefSize, 250, prefSize )
		);

		layout.setVerticalGroup( layout.createSequentialGroup()
			.addComponent( labelInfo )
			.addGap( 25 )

			.addGroup( layout.createParallelGroup()
				.addComponent( labelAID, prefSize, compHeight, prefSize )
				.addComponent( textAID, prefSize, compHeight, prefSize ) )

			.addGap( 25 )
			.addGroup( layout.createParallelGroup()
					.addComponent( labelTrcAmount, prefSize, compHeight, prefSize )
					.addComponent( textTrcAmount, prefSize, compHeight, prefSize ) )

			.addGap( 40 )
			.addComponent( buttonTransaction, prefSize, 50, prefSize )
		);
	}

	final int caPKIndex = 0x03;
	final Binary caPublicKey = Bin( "04167A1CDC01DB24BD26633990CE6A19D2ADA089F958E8B64F90D5F2C37F3E97FF7897D583A73A1EF84BFCAF5950D36256A7C6CF6ADE6FCA9BD73BDDB4F4A836E9" );

	// -----------------------------------------------------------------------------------------------------------------
	private void onTransaction( ActionEvent e )
	{
		main.runScript( "", () ->
		{
			Binary aid = Bin( textAID.getText() );
			MUST( (aid.size() >= 5) && (aid.size() <= 16), "Wrong AID Len" );

			String s = textTrcAmount.getText();
			MUST( (s.length() <= 12) && s.matches( "[0-9]+" ), "Amount must be n 12 (only numbers)" );
			s = Strings.PadLeft( s, 12, '0' );
			Binary amount = Bin( s );
			
			TerminalK8 term = new TerminalK8( main.cr, aid, new ECAlg( new Secp256r1(), new Random( System.nanoTime() ) ) );
			term.addCAPublicKey( caPKIndex, caPublicKey );
			term.select();
			term.getProcessingOptions();
			term.readAFLRecords();
			term.processCertificates();
			term.sess.tlvDB.store( TagEmv.AmountAuthorisedNumeric, amount );
			term.generateAC( 0x40, false );
		} );
	}

	// -----------------------------------------------------------------------------------------------------------------
	 JSONObject toJSON()
	{
		JSONObject jo = new JSONObject();
		jo.put( "Application AID", this.textAID.getText() );
		jo.put( "Transaction Amount", this.textTrcAmount.getText() );
		return jo;
	}

	// -----------------------------------------------------------------------------------------------------------------
	void fromJSON( JSONObject jo )
	{
		this.textAID.setText( jo.getString( "Application AID" ) );
		this.textTrcAmount.setText( jo.getString( "Transaction Amount" ) );
	}

}

