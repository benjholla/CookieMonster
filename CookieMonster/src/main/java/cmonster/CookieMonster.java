package cmonster;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import cmonster.browsers.Browser;
import cmonster.browsers.ChromeBrowser;
import cmonster.browsers.FirefoxBrowser;
import cmonster.browsers.InternetExplorerBrowser;
import cmonster.browsers.SafariBrowser;
import cmonster.cookies.Cookie;

public class CookieMonster {

	private static final String DEFAULT_BROWSER = "chrome";
	private static final String DEFAULT_DOMAIN = "facebook.com";
	
	public static final Map<String,Browser> SUPPORTED_BROWSERS;
	
	static {
		SUPPORTED_BROWSERS = new HashMap<String,Browser>();
		SUPPORTED_BROWSERS.put("chrome", new ChromeBrowser());
		SUPPORTED_BROWSERS.put("firefox", new FirefoxBrowser());
		SUPPORTED_BROWSERS.put("ie", new InternetExplorerBrowser());
		SUPPORTED_BROWSERS.put("safari", new SafariBrowser());
	}
	
	private static final String HELP_NAME = "h";
	private static final String HELP_LONG_NAME = "help";
	private static final String BROWSERS_NAME = "b";
	private static final String BROWSERS_LONG_NAME = "browsers";
	private static final String DOMAINS_NAME = "d";
	private static final String DOMAINS_LONG_NAME = "domains";
	
	public static void main(String[] args) throws IOException {
		
		// create the command line parser
		CommandLineParser parser = new DefaultParser();
		
		// create the Options
		Options options = new Options();
		ArrayList<String> sortedBrowserNames = new ArrayList<String>(SUPPORTED_BROWSERS.keySet());
		Collections.sort(sortedBrowserNames);
		options.addOption(Option.builder(HELP_NAME).longOpt(HELP_LONG_NAME).required(false).hasArg(false).desc("Prints this help menu and exits").build());
		options.addOption(Option.builder(BROWSERS_NAME).longOpt(BROWSERS_LONG_NAME).required(false).hasArgs().argName("browser1,browser2,...").type(String.class).valueSeparator(',')
				.desc("Specifies the target browsers to search for cookie values "
				+ "(supports: " + sortedBrowserNames.toString().replace("[","").replace("]","") + ")").build());
		options.addOption(Option.builder(DOMAINS_NAME).longOpt(DOMAINS_LONG_NAME).required(false).argName("domain1.com,domain2.com,...").hasArgs().valueSeparator(',').type(String.class)
				.desc("Specifies the target domains to search for cookie values").build());

		try {
			// parse the command line arguments
			CommandLine line = parser.parse(options, args);

			// validate that block-size has been set
			if (line.hasOption(HELP_NAME)) {
				printHelp(options);
				System.exit(0);
			}
			
			// get the selected browsers to search
			String[] browsers = null;
			ArrayList<Browser> selectedBrowsers = new ArrayList<Browser>();
			if(line.hasOption(BROWSERS_NAME)) {
				browsers = line.getOptionValues(BROWSERS_NAME);
			} else if(line.hasOption(BROWSERS_LONG_NAME)) {
				browsers = line.getOptionValues(BROWSERS_LONG_NAME);
			}
			if(browsers != null) {
				for(String browser : browsers) {
					if(SUPPORTED_BROWSERS.containsKey(browser)) {
						selectedBrowsers.add(SUPPORTED_BROWSERS.get(browser));
					} else {
						System.err.println("Browser [" + browser + "] is not supported.");
					}
				}
			} else {
				selectedBrowsers.add(SUPPORTED_BROWSERS.get(DEFAULT_BROWSER));
			}
			System.out.println("Selected Browsers: " + selectedBrowsers.toString().replace("[","").replace("]",""));
			
			// get the selected domains to search
			String[] domains;
			if(line.hasOption(DOMAINS_NAME)) {
				domains = line.getOptionValues(DOMAINS_NAME);
			} else {
				domains = new String[] {DEFAULT_DOMAIN};
			}
			System.out.println("Selected Domains: " + Arrays.toString(domains).replace("[","").replace("]",""));
			
			
			// search for the corresponding cookies
			dumpCookies(selectedBrowsers, domains);
		} catch (ParseException e) {
			System.out.println("Invalid arguments:" + e.getMessage());
			printHelp(options);
			System.exit(-1);
		}
	}
	
	private static void printHelp(final Options options) {
		final HelpFormatter formatter = new HelpFormatter();
		final String syntax = "java -jar CookieMonster.jar --browsers=chrome --domain=facebook.com";
		final String usageHeader = "";
		final String usageFooter = "See https://github.com/benjholla/CookieMonster for further details.";
		formatter.printHelp(syntax, usageHeader, options, usageFooter);
	}
	
	private static void dumpCookies(Collection<Browser> browsers, String... domains) {
		System.out.println("============================================================");
		for(String domain : domains) {
			System.out.println("Searching cookies for domain: " + domain);
			System.out.println("============================================================");
			for(Browser browser : browsers) {
				System.out.println("Searching in browser: " + browser.getName());
				System.out.println("============================================================");
				Set<Cookie> cookies = browser.getCookiesForDomain(domain);
				if(cookies.isEmpty()) {
					System.out.println("No cookies found.");
				} else {
					for(Cookie cookie : cookies){
						System.out.println(cookie.toString());
					}
				}
				System.out.println("============================================================");
			}
		}
		System.out.println("============================================================");
		System.out.println("Finished.");
	}

}
