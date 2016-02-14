package cmonster.browsers;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import cmonster.cookies.Cookie;
import cmonster.cookies.DecryptedCookie;
import cmonster.cookies.EncryptedCookie;

public abstract class Browser {
	
	/**
	 * A file that should be used to make a temporary copy of the browser's cookie store
	 */
	protected File cookieStoreCopy = new File(".cookies.db");
	
	/**
	 * Returns all cookies
	 */
	public Set<Cookie> getCookies() {
		HashSet<Cookie> cookies = new HashSet<Cookie>();
		for(File cookieStore : getCookieStores()){
			cookies.addAll(processCookies(cookieStore, null));
		}
		return cookies;
	}
	
	/**
	 * Returns cookies for a given domain
	 */
	public Set<Cookie> getCookiesForDomain(String domain) {
		HashSet<Cookie> cookies = new HashSet<Cookie>();
		for(File cookieStore : getCookieStores()){
			cookies.addAll(processCookies(cookieStore, domain));
		}
		return cookies;
	}

	/**
	 * Returns a set of cookie store locations
	 * @return
	 */
	protected abstract Set<File> getCookieStores();

	/**
	 * Processes all cookies in the cookie store for a given domain or all
	 * domains if domainFilter is null
	 * 
	 * @param cookieStore
	 * @param domainFilter
	 * @return
	 */
	protected abstract Set<Cookie> processCookies(File cookieStore, String domainFilter);

	/**
	 * Decrypts an encrypted cookie
	 * @param encryptedCookie
	 * @return
	 */
	protected abstract DecryptedCookie decrypt(EncryptedCookie encryptedCookie);
	
}
