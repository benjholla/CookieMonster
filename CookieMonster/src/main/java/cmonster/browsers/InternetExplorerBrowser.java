package cmonster.browsers;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import cmonster.cookies.Cookie;
import cmonster.cookies.DecryptedCookie;
import cmonster.cookies.EncryptedCookie;

public class InternetExplorerBrowser extends Browser {

	@Override
	protected Set<File> getCookieStores() {
		HashSet<File> cookieStores = new HashSet<File>();

		// WinXP
		cookieStores.add(new File(System.getProperty("user.home") + "\\Cookies\\"));
		
		// Win7
		cookieStores.add(new File(System.getProperty("user.home") + "\\AppData\\Roaming\\Microsoft\\Windows\\Cookies\\"));

		// Win8
		cookieStores.add(new File(System.getProperty("user.home") + "\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\"));
		
		return cookieStores;
	}

	@Override
	protected Set<Cookie> processCookies(File cookieStore, String domainFilter) {
		// TODO: Implement
		return null;
	}

	@Override
	protected DecryptedCookie decrypt(EncryptedCookie encryptedCookie) {
		// TODO: Implement
		return null;
	}
	
}
