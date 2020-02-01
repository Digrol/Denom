// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com
// Author:  Mihail Buhlin

package org.denom.swing;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.LayoutStyle.ComponentPlacement;
import java.util.function.Supplier;

/**
 * Модальный диалог для ввода данных или подтверждения с кнопками 'Ok' и 'Отмена'.
 * Позволяет проверять введённые данные при нажатии 'Ok'
 * Экземпляр окна-диалога освобождается при закрытии.
 */
@SuppressWarnings("serial")
public class DialogConfirm extends JDialog
{
	/**
	 * Callback, вызываемый по нажатию на кнопку 'Ok'.
	 */
	private Supplier<Boolean> isAccepted;

	/**
	 * Как был закрыт диалог. True - нажата кнопка 'Ok' и isAccepted вернул true.
	 */
	private boolean isOk;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Размер диалога подбирается под content.getPrefferedSize
	 * @param parent - Владелец диалога.
	 * @param title - Заголовок окна диалога.
	 * @param content - Компонент или панель - содержимое диалога.
	 * @param resizable - разрешён ли resize для диалога.
	 */
	public DialogConfirm( JFrame parent, String title, JComponent content, boolean resizable )
	{
		this( parent, title, content, resizable, "ОК", "Отмена" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Кастомизация текста на кнопках. Например: 'Разрешить'-'Запретить', 'Выбрать'-'Закрыть'
	 */
	public DialogConfirm( JFrame parent, String title, JComponent content, boolean resizable,
			String buttonOkText, String buttonCancelText )
	{
		super( parent, title, true );
		setResizable( resizable );

		JButton buttonOk = new JButton( buttonOkText );
		buttonOk.addActionListener( e -> onOk() );

		JButton buttonCancel = new JButton( buttonCancelText );
		buttonCancel.addActionListener( e -> onCancel() );

		addWindowListener( new WindowAdapter()
		{
			public void windowClosing( WindowEvent e )
			{
				onCancel();
			}
		} );

		JPanel panelButtons = new JPanel();
		panelButtons.setBorder( BorderFactory.createEmptyBorder( 10, 10, 10, 10 ) );
		GroupLayout group = new GroupLayout( panelButtons );
		panelButtons.setLayout( group );

		int prefSize = GroupLayout.PREFERRED_SIZE;

		group.setHorizontalGroup( group.createSequentialGroup()
			.addPreferredGap( ComponentPlacement.UNRELATED, 0, Short.MAX_VALUE )
			.addComponent( buttonOk )
			.addGap( 5 )
			.addComponent( buttonCancel )
		);

		group.setVerticalGroup( group.createSequentialGroup()
			.addGroup( group.createParallelGroup()
				.addComponent( buttonOk, prefSize, 30, prefSize )
				.addComponent( buttonCancel, prefSize, 30, prefSize ) )
			);

		JPanel panel = new JPanel( new BorderLayout() );
		panel.add( content, BorderLayout.CENTER );
		panel.add( panelButtons, BorderLayout.SOUTH );
		setContentPane( panel );

		Dimension dim = content.getMinimumSize();
		setMinimumSize( new Dimension( Math.max( dim.width, 200 ), dim.height + 90 ) );

		dim = content.getPreferredSize();
		setSize( dim.width + 10, dim.height + 90 );

		setLocationRelativeTo( parent );

		getRootPane().registerKeyboardAction( e -> onCancel(),
				KeyStroke.getKeyStroke( KeyEvent.VK_ESCAPE, 0 ), JComponent.WHEN_IN_FOCUSED_WINDOW );

		getRootPane().setDefaultButton( buttonOk );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Показать диалог и задать callback, который будет вызван при при нажатии кнопки 'Ок'.
	 * Если он вернёт true - то диалог закроется, false - останется открытым. 
	 * Например, в callback-е можно проверять введённые в диалоге данные и не принимать ввод пользователя
	 * пока не будут введены корректные данные.
	 * @param isAccepted - может быть null, если проверка не нужна.
	 * @return - true, если диалог закрыт кнопкой 'Оk'.
	 */
	public boolean showDialog( Supplier<Boolean> isAccepted )
	{
		this.isAccepted = isAccepted;
		isOk = false;
		setVisible( true );
		return isOk;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void onCancel()
	{
		setVisible( false );
		dispose();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void onOk()
	{
		if( (isAccepted == null) || isAccepted.get() )
		{
			isOk = true;
			setVisible( false );
			dispose();
		}
	}
}
