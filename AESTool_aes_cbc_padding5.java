package com.example.zoujian.test;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class AESTool {

	private static final String ALGORITHM = "AES";
	private static final String MODE = "AES/CBC/PKCS5Padding";
	private static String initialVector = "0000000000000000"; 
	
	public static final char HEX_DIGITS[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	

	public static byte[] encrypt(byte[] data, String key, String iv) throws Exception {
		byte[] keyBytes = Hex2ByteArray(key);
		Key keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
		
		Cipher cipher = Cipher.getInstance(MODE);
		IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
		
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
		return cipher.doFinal(data);
	}
	

	public static String encrypt(String toEnc, String key, String iv) throws Exception{
		return toHexString(encrypt(toEnc.getBytes("UTF-8"), key, iv));
	}
	
	
	public static String decrypt(byte[] data, String key, String iv) throws Exception {
		byte[] keyBytes = Hex2ByteArray(key);
		Key keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
		
		Cipher cipher = Cipher.getInstance(MODE);
		IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
		
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
		return new String(cipher.doFinal(data), "UTF-8").trim();
	}
	
	
	public static String decrypt(String encryptedHEX, String key, String iv) throws Exception{
		return decrypt(Hex2ByteArray(encryptedHEX), key, iv);
	}
	
	
	public static byte[] Hex2ByteArray(String stringHEX) {
		byte[] bufferByte = new byte[stringHEX.length() / 2];
		try {
			List<Integer> bufferls = new ArrayList<Integer>();
			Integer j = 0;
			for (int i = 2; i < stringHEX.length() + 2; i = i + 2) {
				bufferls.add(Integer.decode("0x" + stringHEX.substring(j, i)));
				j = i;
			}
			for (int i = 0; i < bufferls.size(); i++) {
				bufferByte[i] = bufferls.get(i).byteValue();
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return bufferByte;
	}
	
	
	public static String toHexString(byte[] b) {
		StringBuffer buffer = new StringBuffer();
		for (byte ts : b) {
			String hex = Integer.toHexString(ts & 0xff);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			buffer.append(hex);
		}
		return buffer.toString();
	}
	
	
	public static String getMD5(String s) {
		try {
			MessageDigest digest = MessageDigest.getInstance("MD5");
			digest.update(s.getBytes());
			byte messageDigest[] = digest.digest();
			return toHexString(messageDigest);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return "";
	}

	public static void main(String[] args) {
		String keyString  = "12345678901234567890123456789012";
		System.out.println("密钥："+keyString);
		String toEnc = "sdhjshjfhbjfnjdbgfndbgdbgdibgdigbdgbdg";
		System.out.println("加密前："+toEnc);
		try {
			String encryptedHex = encrypt(toEnc, keyString, initialVector);
			System.out.println("加密后："+encryptedHex);
			String decrypted = decrypt(encryptedHex, keyString, initialVector);
			System.out.println("解密后："+decrypted);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
