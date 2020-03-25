// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.net.d5.relay;

public final class RelayCmd
{
	// Relay -> Resource
	public final static int WHO_ARE_YOU         = 0xCDD00101;

	// User -> Relay
	public final static int LIST_RESOURCES      = 0xCDD00001;
	public final static int IS_RESOURCE_PRESENT = 0xCDD00002;

	// User -> Relay
	public final static int SEND_TO             = 0xCDD00003;
	// User -> Relay -> Resource
	public final static int SEND                = 0xCDD00004;

}
