# CookieMonster
A utility for exfiltrating cookies from local browser cookie stores.

## Usage
	Browser chrome = new ChromeBrowser();
	// Set<Cookie> cookies = chrome.getCookies(); // all browser cookies
	Set<Cookie> cookies = chrome.getCookiesForDomain("github.com");
	for(Cookie cookie : cookies){
		System.out.println(cookie.toString());
	}

## Supported Browsers
| **Browser**       | **Support**         |
|-------------------|---------------------|
| Chrome            | Mac, Windows, Linux |
| Firefox           | Not Supported       |
| Internet Explorer | Not Supported       |
| Safari            | Not Supported       |
| Opera             | Not Supported       |
