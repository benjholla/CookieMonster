package cmonster.browsers;

import java.util.Set;

import cmonster.cookies.Cookie;

public interface Browser {
	
	public Set<Cookie> getCookies();
	public Set<Cookie> getCookiesForDomain(String domain);
	
}
