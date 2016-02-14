package cmonster.browsers;

import java.io.File;
import java.util.Set;

import cmonster.cookies.Cookie;

public abstract class Browser {
	
	/**
	 * A file that should be used to make a temporary copy of the browser's cookie store
	 */
	protected File cookieStoreCopy = new File(".cookies.db");
	
	/**
	 * Returns all cookies
	 */
	public abstract Set<Cookie> getCookies();
	
	/**
	 * Returns cookies for a given domain
	 */
	public abstract Set<Cookie> getCookiesForDomain(String domain);
	
}
