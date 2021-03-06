package co.com.quipux.utility.security;


// CIPHER / GENERATORS
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;




/**
 * Administra la informacion de la contrasenha a base de datos
 * 
 * @author <a href="http://www.quipux.com/">Quipux Software</a></br>
 * @version 1.0 <br>
 * <br>
 */



public class EncryptClass {
	

    private Cipher ecipher;
    private Cipher dcipher;
    
    
    
    public static void main (String arg[]){
    	System.out.println("Encriptado: "+new EncryptClass("OSO").encrypt("asd123"));;
    }

    public EncryptClass(SecretKey key, String algorithm) {
       try {
           ecipher = Cipher.getInstance(algorithm);
           dcipher = Cipher.getInstance(algorithm);
           ecipher.init(Cipher.ENCRYPT_MODE, key);
           dcipher.init(Cipher.DECRYPT_MODE, key);
       } catch (NoSuchPaddingException e) {
    	   e.printStackTrace();
       } catch (NoSuchAlgorithmException e) {
    	   e.printStackTrace();
       } catch (InvalidKeyException e) { 
    	   e.printStackTrace();
       }
   }


    public EncryptClass(String passPhrase) {
        // 8-bytes Salt
        byte[] salt = {             (byte)0xA9, (byte)0x9B, (byte)0xC8, (byte)0x32,
        (byte)0x56, (byte)0x34, (byte)0xE3, (byte)0x03        };
        // Iteration count
        int iterationCount = 19;
         try {               KeySpec keySpec = new PBEKeySpec(passPhrase.toCharArray(), salt, iterationCount);
         SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);

         ecipher = Cipher.getInstance(key.getAlgorithm());
         dcipher = Cipher.getInstance(key.getAlgorithm());
         // Prepare the parameters to the cipthers
         AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
         ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
         dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
        } catch (InvalidAlgorithmParameterException e) {
        	e.printStackTrace();
        } catch (InvalidKeySpecException e) {
        	e.printStackTrace();
        } catch (NoSuchPaddingException e) {
        	e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
        	e.printStackTrace();
        } catch (InvalidKeyException e) {
        	e.printStackTrace();

        }
    }



    public String encrypt(String str) {
        try {
            // Encode the string into bytes using utf-8
            byte[] utf8 = str.getBytes("UTF8");
            // Encrypt
            byte[] enc = ecipher.doFinal(utf8);
            // Encode bytes to base64 to get a string
            return new sun.misc.BASE64Encoder().encode(enc);
        } catch (BadPaddingException e) {
        	e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
        	e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
        	e.printStackTrace();
        } 
        return null;
    }


    public String decrypt(String str) {
        try {
            // Decode base64 to get bytes
            byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);
            // Decrypt
            byte[] utf8 = dcipher.doFinal(dec);
            // Decode using utf-8
            return new String(utf8, "UTF8");
        } catch (BadPaddingException e) {
        	e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
        	e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
        	e.printStackTrace();
        } catch (IOException e) {
        	e.printStackTrace();
        }
        return null;
    }
    
    

}

