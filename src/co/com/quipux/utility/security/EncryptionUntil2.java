package co.com.quipux.utility.security;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;



/**
 * @author JavaDigest
 * 
 */
public class EncryptionUntil2 {

	/**
	 * String to hold name of the encryption algorithm.
	 */
	public static final String ALGORITHM = "RSA";

	/**
	 * String to hold the name of the private key file.
	 */
	public static final String PRIVATE_KEY_FILE = "D:/DanielGutierrez/Proyectos/Encripcion/Encripcion/keys/private.key";

	/**
	 * String to hold name of the public key file.
	 */
	public static final String PUBLIC_KEY_FILE = "D:/DanielGutierrez/Proyectos/Encripcion/Encripcion/keys/public.key";

	/**
	 * Generate key which contains a pair of private and public key using 1024 bytes. Store the set of keys in Prvate.key and Public.key files.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	public static void generateKey() {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
			keyGen.initialize(1024);
			final KeyPair key = keyGen.generateKeyPair();

			File privateKeyFile = new File(PRIVATE_KEY_FILE);
			File publicKeyFile = new File(PUBLIC_KEY_FILE);

			// Create files to store public and private key
			if (privateKeyFile.getParentFile() != null) {
				privateKeyFile.getParentFile().mkdirs();
			}
			privateKeyFile.createNewFile();

			if (publicKeyFile.getParentFile() != null) {
				publicKeyFile.getParentFile().mkdirs();
			}
			publicKeyFile.createNewFile();

			// Saving the Public key in a file
			ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
			publicKeyOS.writeObject(key.getPublic());
			publicKeyOS.close();

			// Saving the Private key in a file
			ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
			privateKeyOS.writeObject(key.getPrivate());
			privateKeyOS.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * The method checks if the pair of public and private key has been generated.
	 * 
	 * @return flag indicating if the pair of keys were generated.
	 */
	public static boolean areKeysPresent() {

		File privateKey = new File(PRIVATE_KEY_FILE);
		File publicKey = new File(PUBLIC_KEY_FILE);

		if (privateKey.exists() && publicKey.exists()) {
			return true;
		}
		return false;
	}

	/**
	 * Encrypt the plain text using public key.
	 * 
	 * @param text
	 *            : original plain text
	 * @param key
	 *            :The public key
	 * @return Encrypted text
	 * @throws java.lang.Exception
	 */
	public static byte[] encrypt(String text, PublicKey key) {
		byte[] cipherText = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	/**
	 * Decrypt text using private key.
	 * 
	 * @param text
	 *            :encrypted text
	 * @param key
	 *            :The private key
	 * @return plain text
	 * @throws java.lang.Exception
	 */
	public static String decrypt(byte[] text, PrivateKey key) {
		byte[] dectyptedText = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ALGORITHM);

			// decrypt the text using the private key
			cipher.init(Cipher.DECRYPT_MODE, key);
			dectyptedText = cipher.doFinal(text);

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return new String(dectyptedText);
	}

	/**
	 * Test the EncryptionUntil
	 * @throws Exception 
	 */
	// public static void main(String[] args) {
	//
	// try {
	//
	// // Check if the pair of keys are present else generate those.
	// if (!areKeysPresent()) {
	// // Method generates a pair of keys using the RSA algorithm and stores it
	// // in their respective files
	// generateKey();
	// }
	//
	// final String originalText = "Dispositivo";
	// ObjectInputStream inputStream = null;
	//
	// // Encrypt the string using the public key
	// inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
	// final PublicKey publicKey = (PublicKey) inputStream.readObject();
	// final byte[] cipherText = encrypt(originalText, publicKey);
	//
	// // Decrypt the cipher text using the private key.
	// inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
	// final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
	// final String plainText = decrypt(cipherText, privateKey);
	//
	// // Printing the Original, Encrypted and Decrypted Text
	// System.out.println("Original Text: " + originalText);
	// System.out.println("Encrypted Text: " + Base64.encodeBase64String(cipherText));
	// System.out.println("Decrypted Text: " + plainText);
	//
	// } catch (Exception e) {
	// e.printStackTrace();
	// }
	// }

	public static void main(String[] args) throws Exception {
		//testEncripcion();
		/*byte[] bitEncript = encryptAES("OME648          ", "0123456789abcdef");
		String encript = new String(Hex.encodeHex(bitEncript));
 		System.out.println("encrypted: "+encript+"\n");
		String decrypt = decryptAES(bitEncript, "0123456789abcdef");
		System.out.println("decrypt: "+decrypt+"\n");*/
		testRSAEncrypt();
//		generateKey();
		
	}
	
	
	
	
	private static void testRSAEncrypt() throws FileNotFoundException, IOException, ClassNotFoundException, DecoderException, ParserConfigurationException, TransformerException{
		// Encrypt the string using the public key
				ObjectInputStream inputStream2 = null;
				inputStream2 = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
				
				
				final PublicKey publicKey = (PublicKey) inputStream2.readObject();
				final byte[] cipherText2 = encrypt("asd123", publicKey);
				
				String textoEncriptado = new String(Hex.encodeHex(cipherText2));
				System.out.println("Encriptado  \n"+textoEncriptado);
				
				String cipherText = //textoEncriptado;
						"026a11a8d2395bcf1afc882091d81ff47cb4f25138d98abe2909efb5dcc4b124234a057661a111c5c73e30b2fcf69df6e9595bd6de8645eef6fe60334bba67615b9f8e969b3831ea164f0c498fffa5c572d7f2a598970fd5061dafa69ae41c234fda4b5f7f9bbf1d6a0f25622df6c7aa28223c54650b703ddbd41323ff2b1672";
						
				ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
				PrivateKey privateKey = (PrivateKey) inputStream.readObject();
				String plainText = decrypt(Hex.decodeHex(cipherText.toCharArray()), privateKey);
				System.out.println("Desencriptado\n"+plainText+"\n");
				
				getRSAPublicKeyAsXMLString((RSAPublicKey)publicKey, (RSAPrivateKey)privateKey);
	}
	
	public static void testEncripcion(){
		try {
			final String originalText = "adminadmin";
			ObjectInputStream inputStream = null;

			// Encrypt the string using the public key
			inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
			final PublicKey publicKey = (PublicKey) inputStream.readObject();
			final byte[] cipherText = encrypt(originalText, publicKey);
			
			// Decrypt the cipher text using the private key.
			inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
			final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
			final String plainText = decrypt(cipherText, privateKey);

			RSAPublicKey publicKeyR = (RSAPublicKey) publicKey;
			RSAPrivateKey privateKeyR = (RSAPrivateKey) privateKey;

			String exponente = publicKeyR.getPublicExponent().toString(16);
			String modulo = publicKeyR.getModulus().toString(16);

//			System.out.println("Exponente: " + exponente);
//			System.out.println("Modulo: " + modulo);
//
//			// Printing the Original, Encrypted and Decrypted Text
//			System.out.println("Original Text: " + originalText);
//			System.out.println("Encriptado: " + Base64.encodeBase64String(cipherText));
//			System.out.println("Desencritado: " + plainText);

			// ENCRIPTAR CON MODULO Y EXPONENTE
			RSAPublicKey publicKeyEncriptar = obtenPublicKey(modulo, exponente);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] cifrado = cipher.doFinal("88234061".getBytes());
			char[] charEncriptado = Hex.encodeHex(cifrado);
			String textoEncriptado = new String(charEncriptado);

			System.out.println("Encriptado con MOdulo y Exponente: " + textoEncriptado);

			// textoEncriptado="54b0f133aa0d8f51f0e880ef8065f37087ea70397d5c86bc3670881624e96c1498e035bb9f5c38239e5208c4881f1890c1e927cd3fd2faf2732ee79d8838426e849fae0185ab3f38468c0a8015de33ba3d324410b565dc8c06ec34fe8251b9c6040df5cf5dac9d9e25819336130b3464be8d1a6f912bd9ee16c3cd63204dd6a2";

			// DESSSSSSSSENCRIPTAR CON MODULO Y EXPONENTE
			Cipher cipherDes = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] desencriptado = Hex.decodeHex(textoEncriptado.toCharArray());
			byte[] desci = cipher.doFinal(desencriptado);
			String textoDesencriptado = new String(desci, "UTF-8");

			System.out.println("DESEncriptado con MOdulo y Exponente: " + textoDesencriptado);

			getRSAPublicKeyAsXMLString(publicKeyR, privateKeyR);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static RSAPublicKey obtenPublicKey(String modulo, String exponente) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec publicKey = new RSAPublicKeySpec(new BigInteger(modulo, 16), new BigInteger(exponente, 16));
		PublicKey pubKey = fact.generatePublic(publicKey);
		return (RSAPublicKey) pubKey;
	}

	/**
	 * Gets the RSA Public key as XML string.
	 * 
	 * @param key
	 *            RSAPublicKey
	 * @return String XML representation of RSA Public Key.
	 * @throws UnsupportedEncodingException
	 * @throws ParserConfigurationException
	 * @throws TransformerException
	 */
	public static void getRSAPublicKeyAsXMLString(RSAPublicKey key, RSAPrivateKey privateKey) throws UnsupportedEncodingException,
			ParserConfigurationException, TransformerException {
		Document xml = getRSAPublicKeyAsXML(key);

		Document xmlPrivate = getRSAPrivateKeyAsXML(privateKey);
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		StringWriter sw = new StringWriter();
		transformer.transform(new DOMSource(xml), new StreamResult(sw));
		System.out.println("XML: " + sw.getBuffer().toString());
		transformer.transform(new DOMSource(xmlPrivate), new StreamResult(sw));
		System.out.println("XML private: " + sw.getBuffer().toString());
	}

	/**
	 * Gets the RSA Public Key as XML. The idea is to make the key readable for .Net platform. The generated key is compatible with .Net key
	 * structure.
	 * 
	 * @param key
	 *            RSAPublicKey
	 * @return Document XML document.
	 * @throws ParserConfigurationException
	 * @throws UnsupportedEncodingException
	 */
	public static Document getRSAPublicKeyAsXML(RSAPublicKey key) throws ParserConfigurationException, UnsupportedEncodingException {
		Document result = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
		Element rsaKeyValue = result.createElement("RSAKeyValue");
		result.appendChild(rsaKeyValue);
		Element modulus = result.createElement("Modulus");
		rsaKeyValue.appendChild(modulus);
		byte[] modulusBytes = key.getModulus().toByteArray();

		modulusBytes = stripLeadingZeros(modulusBytes);

		// modulusBytes = modulusBytes.toString().replaceFirst("^0*", modulusBytes.toString()).getBytes();

		// KeyManager.write("c:\\mod.c",
		// new sun.misc.BASE64Encoder().encode(modulusBytes)); //Stored it for testing purposes

		modulus.appendChild(result.createTextNode(new String(Base64Coder.encode(modulusBytes))));

		Element exponent = result.createElement("Exponent");
		rsaKeyValue.appendChild(exponent);
		byte[] exponentBytes = key.getPublicExponent().toByteArray();
		// KeyManager.write("C:\\exponenet.c",
		// new sun.misc.BASE64Encoder().encode(exponentBytes)); //stored it for testing purposes
		exponent.appendChild(result.createTextNode(new String(Base64Coder.encode(exponentBytes))));
		return result;
	}

	public static Document getRSAPrivateKeyAsXML(RSAPrivateKey key) throws ParserConfigurationException, UnsupportedEncodingException {
		Document result = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
		Element rsaKeyValue = result.createElement("RSAKeyValue");
		result.appendChild(rsaKeyValue);
		Element modulus = result.createElement("Modulus");
		rsaKeyValue.appendChild(modulus);
		byte[] modulusBytes = key.getModulus().toByteArray();

		modulusBytes = stripLeadingZeros(modulusBytes);

		// modulusBytes = modulusBytes.toString().replaceFirst("^0*", modulusBytes.toString()).getBytes();

		// KeyManager.write("c:\\mod.c",
		// new sun.misc.BASE64Encoder().encode(modulusBytes)); //Stored it for testing purposes

		modulus.appendChild(result.createTextNode(new String(Base64Coder.encode(modulusBytes))));

		Element exponent = result.createElement("Exponent");
		rsaKeyValue.appendChild(exponent);
		byte[] exponentBytes = key.getPrivateExponent().toByteArray();
		// KeyManager.write("C:\\exponenet.c",
		// new sun.misc.BASE64Encoder().encode(exponentBytes)); //stored it for testing purposes
		exponent.appendChild(result.createTextNode(new String(Base64Coder.encode(exponentBytes))));
		return result;
	}

	/**
	 * Utility method to delete the leading zeros from the modulus.
	 * 
	 * @param a
	 *            modulus
	 * @return modulus
	 */
	public static byte[] stripLeadingZeros(byte[] a) {
		int lastZero = -1;
		for (int i = 0; i < a.length; i++) {
			if (a[i] == 0) {
				lastZero = i;
			} else {
				break;
			}
		}
		lastZero++;
		byte[] result = new byte[a.length - lastZero];
		System.arraycopy(a, lastZero, result, 0, result.length);
		return result;
	}
	
	static String IV = "AAAAAAAAAAAAAAAA";
	
	 public static byte[] encryptAES(String plainText, String encryptionKey) throws Exception {
		    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
		    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
		    cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
		    return cipher.doFinal(plainText.getBytes("UTF-8"));
		  }
		 
		  public static String decryptAES(byte[] cipherText, String encryptionKey) throws Exception{
		    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
		    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
		    cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
		    return new String(cipher.doFinal(cipherText),"UTF-8");
		  }

}