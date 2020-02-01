// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.swing;

import java.awt.*;
import javax.swing.*;
import javax.swing.GroupLayout.*;

import static org.denom.Ex.*;

/**
 * Панель для ввода пароля с ограничением длины.
 * Опция - с подтверждением.
 */
@SuppressWarnings("serial")
public class PanelPassword extends JPanel
{
	public String password = "";

	private JPasswordField textPassword;
	private JPasswordField textConfirmPassword = null;

	private final int minLen;
	private final int maxLen;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * labelText - может быть пустым.
	 * withConfirm - true - 2 поля: Пароль или подтверждение; иначе - только поле для пароля.
	 */
	public PanelPassword( int minLen, int maxLen, String labelText, boolean withConfirm )
	{
		this.minLen = minLen;
		this.maxLen = maxLen;

		setBorder( BorderFactory.createEmptyBorder( 10, 10, 10, 10 ) );

		int prefSize = GroupLayout.PREFERRED_SIZE;
		int EDIT_WIDTH = 250;
		int EDIT_HEIGHT = 30;

		GroupLayout group = new GroupLayout( this );
		setLayout( group );

		JLabel labelPassword = new JLabel( "Пароль:" );
		textPassword = new JPasswordField( maxLen );
		textPassword.setDocument( SwingUtils.createLimitedSizeDocument( maxLen ) );
		textPassword.setToolTipText( "от " + minLen + " до " + maxLen + " символов." );

		ParallelGroup horizGroup = group.createParallelGroup();
		group.setHorizontalGroup( horizGroup );
		SequentialGroup vertGroup = group.createSequentialGroup();
		group.setVerticalGroup( vertGroup);

		if( !labelText.isEmpty() )
		{
			JLabel labelInfo = new JLabel( labelText );
			labelInfo.setForeground( new Color( 50, 50, 155 ) );
	
			horizGroup.addComponent( labelInfo );
			vertGroup.addComponent( labelInfo );
		}
		vertGroup.addGap( 15 );

		horizGroup.addGroup( group.createSequentialGroup()
			.addComponent( labelPassword, prefSize, 90, prefSize )
			.addComponent( textPassword, prefSize, EDIT_WIDTH, prefSize ) );

		vertGroup.addGroup( group.createParallelGroup()
			.addComponent( labelPassword, prefSize, EDIT_HEIGHT, prefSize )
			.addComponent( textPassword, prefSize, EDIT_HEIGHT, prefSize ) );

		if( withConfirm )
		{
			JLabel labelConfirmPassword = new JLabel( "Повторите:" );
			textConfirmPassword = new JPasswordField( maxLen );
			textConfirmPassword.setDocument( SwingUtils.createLimitedSizeDocument( maxLen ) );
			textConfirmPassword.setToolTipText( "от " + minLen + " до " + maxLen + " символов." );

			horizGroup.addGroup( group.createSequentialGroup()
				.addComponent( labelConfirmPassword, prefSize, 90, prefSize )
				.addComponent( textConfirmPassword, prefSize, EDIT_WIDTH, prefSize ) );

			vertGroup.addGap( 10 );
			vertGroup.addGroup( group.createParallelGroup()
				.addComponent( labelConfirmPassword, prefSize, EDIT_HEIGHT, prefSize )
				.addComponent( textConfirmPassword, prefSize, EDIT_HEIGHT, prefSize ) );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public boolean onOk()
	{
		try
		{
			textPassword.requestFocusInWindow();
			String password = new String( textPassword.getPassword() );
			if( (password.length() < minLen) || (password.length() > maxLen) )
				THROW( "Длина пароля должна быть от " + minLen + " до " + maxLen + " символов." );

			if( textConfirmPassword != null )
			{
				textConfirmPassword.requestFocusInWindow();
				String confirmedPwd = new String( textConfirmPassword.getPassword() );
				MUST( confirmedPwd.equals( password ), "Пароли не совпадают." );
			}
			this.password = password;

			return true;
		}
		catch( Throwable ex )
		{
			SwingUtils.showMessage( this, ex.getMessage(), "Ошибка ввода", JOptionPane.WARNING_MESSAGE );
			return false;
		}
	}
}
