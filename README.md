# CookieMonster
A utility for exfiltrating cookies from local browser cookie stores.

## CLI Usage
	java -jar CookieMonster.jar --browsers=chrome --domains=facebook.com

## Library Usage
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
| Firefox           | Only Basic Support  |
| Internet Explorer | Not Supported (Yet) |
| Safari            | Not Supported (Yet) |
| Opera             | Not Supported (Yet) |

## Building

To build the project clean run maven at the root of the `CookieMonster` project.

`mvn clean install -U`

The build result will be at `CookieMonster/target`.

The `fat` jar includes all necessary dependencies.