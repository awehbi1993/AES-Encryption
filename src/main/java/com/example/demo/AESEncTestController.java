package com.example.demo;

//import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.fontbox.util.Charsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AESEncTestController {
	static Logger logger = LoggerFactory.getLogger(AESEncTestController.class);
	private static final String keyy = "ZZHHYYTTUUHHGGRR";
	private static final String IVV = "AAACCCDDDYYUURRS";
	private static final String SALTVALUE = "abcdefg";
	public static final int GCM_TAG_LENGTH = 16;

	@RequestMapping("/")
	public String index() {
		return "The server is online";
	}
	// if we want to use stored key and IV
	@RequestMapping(value = "/AES", method = RequestMethod.POST)
	public Byte singleFileUpload(@RequestParam("file") MultipartFile Mfile) throws Exception {
		File file = new File("src/main/resources/targetFile.tmp");
		InputStream initialStream = Mfile.getInputStream();
		byte[] buffer = new byte[initialStream.available()];
		initialStream.read(buffer);
		try (OutputStream outStream = new FileOutputStream(file)) {
		    outStream.write(buffer);
		}
//		Mfile.transferTo(file);
//		FileUtils.readFileToString(Mfile, "UTF-8");
		String f = readData(file);
		String name = Mfile.getName();
		/*TODO: temp file to load file in it instead of doing the process on memory*/
		if (f.equals(null)) {
			return (null);
		} else {

// generate the key that we will use it

			byte[] byteOfKey = keyy.getBytes("UTF-8");
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] key = md.digest(byteOfKey);
			logger.info("key" + "  " + key.toString());
			// generate IV
			byte[] IV = IVV.getBytes();
//			SecureRandom random = new SecureRandom();
//			random.nextBytes(IV);
			logger.info("IV" + "  " + IV.toString());
			byte[] cipherText = encrypt(f.getBytes(), key, IV, name);
			logger.info(cipherText.length + "");
			logger.info("Encrypted Text : " + Base64.getEncoder().encodeToString(cipherText));
			logger.info("cipher: " + cipherText);

			byte[] decryptedText = decrypt(cipherText, key, IV);
			logger.info("DeCrypted Text : " + decryptedText, Charsets.UTF_16);
		}
		return (null);
	}
	// if we want to use key and IV uploaded with the document 
	@RequestMapping(value = "/AESWithKey", method = RequestMethod.POST)
	public Byte singleFileUploadwithkey(@RequestParam("file") MultipartFile Mfile, 
			@RequestParam("key") String Key,
			@RequestParam("IV") String Iv) throws Exception {
		// convert multipart file into string
		File file = new File("src/main/resources/targetFile.tmp");
		InputStream initialStream = Mfile.getInputStream();
		byte[] buffer = new byte[initialStream.available()];
		initialStream.read(buffer);
		try (OutputStream outStream = new FileOutputStream(file)) {
		    outStream.write(buffer);
		}
		String f = readData(file);
		String name = file.getName();
		String keyyy = Key;
		String Ivvv = Iv;
// if we want to use stored key and IV  
		if (f.equals(null)) {
			return (null);
		} else {

			byte[] byteOfKey = keyyy.getBytes("UTF-8");
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] k = md.digest(byteOfKey);
			logger.info("key" + "  " + k.toString());
			// generate IV
			byte[] InV = Ivvv.getBytes();
			SecureRandom random = new SecureRandom();
			random.nextBytes(InV);
			logger.info("IV" + "  " + InV.toString());
			//perform encryption
			byte[] cipherText = encrypt(f.getBytes(), k, InV, name);
			logger.info(cipherText.length + "");
			logger.info("Encrypted Text : " + Base64.getEncoder().encodeToString(cipherText));
			logger.info("cipher: " + cipherText);
			// perform decryption 
			byte[] decryptedText = decrypt(cipherText, k, InV);
			logger.info("DeCrypted Text : " + decryptedText, Charsets.UTF_16);
		}
		return (null);
	}

	public static byte[] encrypt(byte[] plaintext, byte[] key, byte[] IV, String name) throws Exception {
		
		//create factory for secret key
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  
		
		//CREATE KEY SPECS	
		KeySpec spec = new PBEKeySpec((key.toString()).toCharArray(), SALTVALUE.getBytes(), 65536, 256);  
	    SecretKey tmp = factory.generateSecret(spec);
		
	    // Create SecretKeySpec
		SecretKeySpec keySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

		// Create GCMParameterSpec
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
		
		// Get Cipher Instance
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		
		// Initialize Cipher for ENCRYPT_MODE
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

		// Perform Encryption
		byte[] cipherText = cipher.doFinal(plaintext);
		BufferedWriter writer = new BufferedWriter((new OutputStreamWriter(
		          new FileOutputStream(name),"utf-8")));
		writer.write(cipherText + "");
		writer.close();
		return cipherText;
	}

	public static byte[] decrypt(byte[] cipherText, byte[] key, byte[] IV) throws Exception {
		// Get Cipher Instance
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

		//create factory for secret key
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  
		
		//CREATE KEY SPECS	
		KeySpec spec = new PBEKeySpec((key.toString()).toCharArray(), SALTVALUE.getBytes(), 65536, 256);  
		SecretKey tmp = factory.generateSecret(spec);
		
		// Create SecretKeySpec
		SecretKeySpec keySpec = new SecretKeySpec(tmp.getEncoded(), "AES");
		// Create IvParameterSpec

		// Create GCMParameterSpec
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

		// Initialize Cipher for DECRYPT_MODE
		cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

		// Perform Decryption
		byte[] decryptedText = cipher.doFinal(cipherText);
		logger.info("decrypted: " + new String(decryptedText));
		return (decryptedText);
	}
	public static String readData(File file) throws FileNotFoundException {
		try {
			BufferedReader reader = new BufferedReader(new FileReader(file));
			StringWriter w = new StringWriter();
			try {
				String line = reader.readLine();
				while (line != null) {
					w.append(line).append("\n");
					line = reader.readLine();
				}

				return w.toString();
			} finally {
				reader.close();
				w.close();
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			return "";
		}
	}

}
