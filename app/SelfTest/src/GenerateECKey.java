
import org.denom.log.*;
import org.denom.d5.relay.RelaySigner;
import org.denom.format.JSONObject;

//import static org.denom.Binary.Bin;
//import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
public class GenerateECKey
{
	static ILog log = new LogConsole();

	public static void main( String[] args )
	{
		RelaySigner signer = new RelaySigner();
		signer.generateKeyPair();

		JSONObject joKey = new JSONObject();
		signer.writePrivateKeyToJSON( joKey );

		JSONObject jo = new JSONObject();
		jo.put( "Key", joKey );

		jo.save( "PrivateKey.json", 4 );
	}
}