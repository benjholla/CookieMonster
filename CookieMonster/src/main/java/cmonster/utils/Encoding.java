package cmonster.utils;

import org.apache.commons.codec.binary.Base64;

public class Encoding {

	public static String base64Encode(String input){
		return new String(Base64.encodeBase64(input.getBytes()));
	}
	
	public static String base64Decode(String input){
		return new String(Base64.decodeBase64(input.getBytes()));
	}
	
}
