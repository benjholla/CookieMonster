package cmonster;

import java.io.IOException;
import java.util.Set;

import cmonster.browsers.ChromeBrowser;
import cmonster.cookies.Cookie;

public class Test {

	public static void main(String[] args) throws IOException {
		ChromeBrowser chrome = new ChromeBrowser();
		Set<Cookie> cookies = chrome.getCookiesForDomain("iseage.org");
		for(Cookie cookie : cookies){
			System.out.println(cookie.toString());
		}
	}

}
