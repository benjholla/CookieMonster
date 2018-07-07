package cmonster;

import java.io.IOException;
import java.util.Set;

import cmonster.browsers.ChromeBrowser;
import cmonster.cookies.Cookie;

public class CookieMonster {

	private static final String DEFAULT_DOMAN = "facebook.com";
	
	public static void main(String[] args) throws IOException {
		System.out.println("Usage: [-d | --domain]	A domain to search and retrieve cookies values. (default: facebook.com)");
		System.out.println("Example Usage: java -jar CookieMonster.jar --domain=facebook.com");
		if(args.length > 0) {
			for(int i=0; i<args.length; i++) {
				String option = args[i++];
				String domain = DEFAULT_DOMAN;
				if(option.equals("-d")) {
					if(i < args.length) {
						domain = args[i];
					} else {
						System.err.println("Please specify a target domain!");
					}
				} else if(option.equals("--domain=")) {
					if(i < args.length) {
						domain = args[i];
					} else {
						System.err.println("Please specify a target domain!");
					}
				}
				dumpCookies(domain);
			}
		} else {
			dumpCookies(DEFAULT_DOMAN);
		}
	}
	
	private static void dumpCookies(String domain) {
		ChromeBrowser chrome = new ChromeBrowser();
		Set<Cookie> cookies = chrome.getCookiesForDomain(domain);
		for(Cookie cookie : cookies){
			System.out.println(cookie.toString());
		}
	}

}
