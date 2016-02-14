package cmonster.utils;

import java.awt.Desktop;
import java.io.File;

public class Decoy {

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
