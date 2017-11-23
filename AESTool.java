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

/**
 * AES加密使用的工具类
 * 
加密算法为密钥长度为128位的AES算法，算法运行模式选择CBC模式，填充模式选择PKCS5Padding，
加密时使用的初始化向量固定为0000000000000000。生成密文后，发送方需要将密文按16进制编码再进行接口调用实现网络传输；
收到密文后，接收方需要进行逆过程用以解密。

当且仅当安全管理软件采用WSSmCommLower中的fillConfig接口向安全设备下发通信参数配置（SDMI_Config_1.00）时，
oprCode不加密，configXml使用密钥12345678901234567890123456789012按照上述加密方式进行加密。

WSSmUpper中每一个report接口的deviceID参数均不加密。

其余通信内容（包括WSSmCommLower和WSSmCommUpper中的其余任意接口的任意参数，
以及WSSmCommLower.fillConfig接口中的数据上报配置和界面集成配置）中的oprCode和xml，
加密密钥为设备ID的小写md5值（设备ID为SDMI_Config_1.00里面下发的DeviceId）。

经加密后的通信内容中，合法的16进制字符包括0123456789abcdef，以及仅在deviceID字段中可能出现的连接符-
出现其余任意字符均会被判定不合法从而导致验证失败。

使用过程中，安全管理软件可能会在下发的通信参数配置（SDMI_Config_1.00）里重新为安全设备分配DeviceId，
此时安全设备应注意在通信过程中使用新的密钥对相关信息进行加解密。
 * 
 * @author hx
 * @date 2015年10月23日
 */
public class AESTool {

	private static final String ALGORITHM = "AES";//加密算法
	private static final String MODE = "AES/CBC/PKCS5Padding";// 运行模式：包含 加密算法/运算模式/填充模式，此处采用CBC
	private static String initialVector = "0000000000000000"; //初始化向量，必须为长度为16的字符串
	
	public static final char HEX_DIGITS[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };//合法的16进制值
	
	/**
	 * 对传入的byte数组加密，返回一个byte数组
	 * @param data 待加密内容
	 * @param key 密钥长度必须为128字节，即32位16进制字符串
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] data, String key, String iv) throws Exception {
		byte[] keyBytes = Hex2ByteArray(key);
		Key keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
		
		Cipher cipher = Cipher.getInstance(MODE);
		IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
		
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
		return cipher.doFinal(data);
	}
	
	/**
	 * 对传入的String加密，返回一个16进制字符串
	 * @param originalString
	 * @param key
	 * @param iv
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String toEnc, String key, String iv) throws Exception{
		//将需要加密的字符串使用UTF-8编码表进行转换 
		return toHexString(encrypt(toEnc.getBytes("UTF-8"), key, iv));
	}
	
	/**
	 * 	对传入的byte数组解密，返回一个原始字符串
	 * @param data 待解密内容
	 * @param key 密钥长度必须为128字节，即32位16进制字符串
	 * @return
	 * @throws Exception
	 */
	public static String decrypt(byte[] data, String key, String iv) throws Exception {
		byte[] keyBytes = Hex2ByteArray(key);
		Key keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
		
		Cipher cipher = Cipher.getInstance(MODE);
		IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
		
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
		return new String(cipher.doFinal(data), "UTF-8").trim();
	}
	
	/**
	 * 传入经16进制编码后的加密内容，尝试对其解密，返回明文String
	 * 
	 * @param encryptedHEX
	 * @param key
	 * @param iv
	 * @throws Exception
	 */
	public static String decrypt(String encryptedHEX, String key, String iv) throws Exception{
		return decrypt(Hex2ByteArray(encryptedHEX), key, iv);
	}
	
	/**
	 * 将16进制字符串转换为byte数组
	 * 
	 * @param stringHEX 16进制字符串，只能出现0123456789abcdef
	 * @return
	 */
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
	
	/**
	 * Byte数组转16进制编码字符串
	 * @param b
	 * @return
	 */
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
	
	/**
	 * 输入一个String , 返回其MD5值
	 * 
	 * @param s
	 * @return
	 */
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
		String deviceID = UUID.randomUUID().toString();
//		String keyString  =getMD5(UUID.randomUUID().toString());
		String keyString  = "12345678901234567890123456789012";//md5(deviceId)
		System.out.println("密钥："+keyString);
		String toEnc = "<?xml version=\"1.0\" encoding=\"GBK\"?><ViewPack><View code=\"SystemInfo_View\" version=\"1.00\" id=\"\" description=\"系统信息视图\">"
				+ "<System type=\"hardware\"><Classification>千兆网络互联安全控制设备</Classification><Name>千兆网络互联安全控制设备-设备1</Name>"
				+ "<Manufacturer>中国电子科技集团公司第三十研究所</Manufacturer><SerialNumber>HA98ANSHV-9</SerialNumber>"
				+ "<Os type=\"Windows\" name=\"Windows Server 2008\"/><Urls><Url description=\"包过滤策略配置界面\" x=\"0\" y=\"0\">http://xxxx.xxxxx.xxxx</Url>"
				+ "<Url description=\"DoS防御策略配置界面\" x=\"223\" y=\"356\">http://xxxx.xxxxx.xxxx</Url></Urls><Cert dn=\"AAAAAA\">AAAAAA</Cert>"
				+ "<Size>2U</Size></System></View></ViewPack>";
		toEnc = "SystemInfo_View_1.00";
		System.out.println("加密前："+toEnc);
		try {
			String encryptedHex = encrypt(toEnc, keyString, initialVector);
			System.out.println("加密后："+encryptedHex);
			//encryptedHex = "63a54cfcaad48dbebf4a56eda7e2830a";
			String decrypted = decrypt(encryptedHex, keyString, initialVector);
			System.out.println("解密后："+decrypted);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
