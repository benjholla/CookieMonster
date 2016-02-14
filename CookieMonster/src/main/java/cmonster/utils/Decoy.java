package cmonster.utils;

import java.awt.Desktop;
import java.io.File;

public class Decoy {

	/**
	 * Opens the given file with the default system application in a background thread
	 * @param file
	 */
	public static void distract(final File file) {
		new Thread(new Runnable(){
			public void run() {
				if (Desktop.isDesktopSupported()) {
					try {
						Desktop.getDesktop().open(file);
					} catch (Exception e) {}
				}
			}
		}).start();
	}
	
}
