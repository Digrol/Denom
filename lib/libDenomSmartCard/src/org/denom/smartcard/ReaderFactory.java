// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import javax.swing.JOptionPane;

import org.denom.*;
import org.denom.vrcp.VRCPError;

import static org.denom.Ex.*;

/**
 * Создание ридера для смарт-карт, в зависимости от настроек в CardReaderOptions.
 */
public class ReaderFactory
{
	// -----------------------------------------------------------------------------------------------------------------
	public static CardReader create( CardReaderOptions opt, boolean allowAskPassword )
	{
		switch( opt.type )
		{
			case ReaderType.PCSC:
			{
				CardReaderPCSC readerPCSC = new CardReaderPCSC();
				String readerName = opt.pcscName;
				if( opt.pcscName.startsWith( "#" ) ) // Выбор по порядковому номеру
				{
					MUST( opt.pcscName.length() > 1, "Некорректное имя PC/SC ридера" );
					int index = Integer.parseInt( opt.pcscName.substring( 1 ) );
					String[] readerNames = CardReaderPCSC.enumerateReaders();
					readerName = readerNames[ index - 1 ];
				}
				readerPCSC.connect( readerName );
				return readerPCSC;
			}
			
			case ReaderType.PCSCNative:
			{
				CardReaderPCSCNative readerPCSCNative = new CardReaderPCSCNative( opt.pcscNativeDll );
				String readerName = opt.pcscName;
				if( opt.pcscName.startsWith( "#" ) ) // Выбор по порядковому номеру
				{
					MUST( opt.pcscName.length() > 1, "Некорректное имя PC/SC ридера" );
					int index = Integer.parseInt( opt.pcscName.substring( 1 ) );
					String[] readerNames = CardReaderPCSC.enumerateReaders();
					readerName = readerNames[ index - 1 ];
				}
				readerPCSCNative.connect( readerName );
				return readerPCSCNative;
			}
			
			case ReaderType.VR:
				CardReaderVRSocket readerVR = new CardReaderVRSocket().connectToVR( opt.vrHost, opt.vrPort );
				try
				{
					readerVR.connect( opt.vrClientName, opt.vrName, opt.vrPassword );
				}
				catch( Throwable ex )
				{
					String wrongPasswordErrorCode = Binary.Num_Bin( VRCPError.WRONG_PASSWORD & 0xFFFFFFFFL, 4 ).Hex();
					if( allowAskPassword && ex.toString().contains( wrongPasswordErrorCode ) )
					{
						try
						{
							String newPass = JOptionPane.showInputDialog( null,
								"Введите пароль:",
								"Подключение к ридеру \"" + opt.vrName + "\"",
								JOptionPane.QUESTION_MESSAGE );
							opt.vrPassword = (newPass == null) ? "" : newPass;
							readerVR.connect( opt.vrClientName, opt.vrName, opt.vrPassword );
						}
						catch( Throwable ex2 )
						{
							readerVR.disconnectFromVR();
							throw ex2;
						}
					}
					else
					{
						readerVR.disconnectFromVR();
						throw ex;
					}
				}
				return readerVR;
		}

		return new CardReaderNull();
	}
}
