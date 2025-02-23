// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8.struct;

import org.denom.Binary;

import static org.denom.Binary.Bin;

/**
 * EMV Сontactless Book C-8, Kernel 8 Specification v1.1, Annex A, A.1.98 Outcome Parameter Set.
 */
public class OutcomeParameterSet
{
	public Binary bin = Bin( 8 );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * KS.2
	 * Initialise Outcome Parameter Set 
	 */
	public void onInitKernel8()
	{
		setStatus( STATUS_NA );
		setStart( START_NA );
		bin.set( 2, 0b1111_0000 ); // Online Response Data = NA
		setCVM( CVM_NA );
		setB5Bit( BIT_DISCRETIONARY_DATA );
		setAlternateInterface( ALT_INTF_NA );
		setFieldOffRequest( 0xFF );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static final int STATUS_APPROVED              = 0b0001_0000; // 0x10
	public static final int STATUS_DECLINED              = 0b0010_0000; // 0x20
	public static final int STATUS_ONLINE_REQUEST        = 0b0011_0000; // 0x30
	public static final int STATUS_END_APPLICATION       = 0b0100_0000; // 0x40
	public static final int STATUS_SELECT_NEXT           = 0b0101_0000; // 0x50
	public static final int STATUS_TRY_ANOTHER_INTERFACE = 0b0110_0000; // 0x60
	public static final int STATUS_TRY_AGAIN             = 0b0111_0000; // 0x70
	public static final int STATUS_NA                    = 0b1111_0000; // 0xF0

	/**
	 * Задать Status в b1.
	 */
	public void setStatus( int status )
	{
		bin.set( 0, status );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static final int START_A  = 0b0000_0000; // 0x00
	public static final int START_B  = 0b0001_0000; // 0x10
	public static final int START_C  = 0b0010_0000; // 0x20
	public static final int START_D  = 0b0011_0000; // 0x30
	public static final int START_NA = 0b1111_0000; // 0xF0

	/**
	 * Задать Start в b2.
	 */
	public void setStart( int start )
	{
		bin.set( 1, start );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static final int CVM_NO_CVM                     = 0b0000_0000; // 0x00
	public static final int CVM_OBTAIN_SIGNATURE           = 0b0001_0000; // 0x10
	public static final int CVM_ONLINE_PIN                 = 0b0010_0000; // 0x20
	public static final int CVM_CONFIRMATION_CODE_VERIFIED = 0b0011_0000; // 0x30
	public static final int CVM_NA                         = 0b1111_0000; // 0xF0

	/**
	 * Задать CVM в b4.
	 */
	public void setCVM( int cvm )
	{
		bin.set( 3, cvm );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Номера битов в байте. От 0 до 7
	 */
	public static final int BIT_UI_REQUEST_ON_OUTCOME = 7; // 0x80
	public static final int BIT_UI_REQUEST_ON_RESTART = 6; // 0x40
	public static final int BIT_DATA_RECORD           = 5; // 0x20
	public static final int BIT_DISCRETIONARY_DATA    = 4; // 0x10
	public static final int BIT_RECIEPT               = 3; // 0x08

	/**
	 * Задать бит в b5.
	 */
	public void setB5Bit( int bitNum )
	{
		bin.setBit( 4, bitNum );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static final int ALT_INTF_CONTACT_CHIP = 0b0001_0000; // 0x10
	public static final int ALT_INTF_MAG_STRIPE   = 0b0010_0000; // 0x20
	public static final int ALT_INTF_NA           = 0b1111_0000; // 0xF0

	public void setAlternateInterface( int pref )
	{
		bin.set( 5, pref );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * 0xFF - NA
	 * other - Hold time in units of 100 ms
	 */
	public void setFieldOffRequest( int t )
	{
		bin.set( 6, t );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param t - Removal Timeout in units of 100 ms.
	 */
	public void setRemovalTimeout( int t )
	{
		bin.set( 7, t );
	}

}
