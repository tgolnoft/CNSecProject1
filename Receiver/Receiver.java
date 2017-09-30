import java.security.*;
import java.util.*;
import java.security.spec.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.Files;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;




public class Receiver{

    static String IV = "AAAAAAAAAAAAAAAA"; //Initialization vector 
    static int BUFFER_SIZE = 32*1024;
    //static Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    
    public static void main(String[] args) throws Exception {
    
     
     //Symmetric key and PrivateKey y
    
    Scanner scan = new Scanner(System.in);
    PrivateKey privKeyY = Readers.readPrivKeyFromFile(Readers.Y_PRIV_FILE_NAME);
    byte[] symkey = Readers.readSymKeyFromFile(Readers.SYM_KEY_FILE_NAME);
    System.out.print("Input the name of the message file: ");
    String fname = scan.nextLine(); //messagePlainText will be saved here 
    
    RSADecrypt(privKeyY);
    
    
   // taking the first 32 bytes and separating the message 
    byte[] dd= Files.readAllBytes(Paths.get("message.add-msg"));
    byte[] authDigest = Arrays.copyOfRange(dd, 0, 32);
    byte[] messagePlainText = Arrays.copyOfRange(dd, 32, dd.length); 
    Files.write(Paths.get(fname), messagePlainText);
    
    //AES DECRYPTION
    byte[] aesDecrypted = AESdecrypt(authDigest, symkey);
    //Hex Display 
    System.out.println("AES-DE(SHA256(m)): ");
    for(int i = 0; i < aesDecrypted.length; i++){
      System.out.print(String.format("%2X ", aesDecrypted[i]));
      if(i == 15) System.out.print("\n");
    }
    Files.write(Paths.get("message.dd"), aesDecrypted);
 	
    //SHA256(M)
    compareMessage(fname); 
    //SHA256 of messagePlaintext to test if correct 
 	
 	
 	
  } //End Main 
          
	
  //BLOCK Decryption 
  public static void RSADecrypt(PrivateKey privKeyY)throws Exception{
    byte[] file = Files.readAllBytes(Paths.get("message.rsacipher"));
    SecureRandom random = new SecureRandom();
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, privKeyY, random);
    try{
      Files.delete(Paths.get("message.add-msg"));
    }catch (Exception x){
      //file doesn't exist
    }
    try{
      Files.createFile(Paths.get("message.add-msg"));
    }catch(Exception x){

    }
    for(int x = 0; x < file.length; x+=128){
      int last = (x+128>=file.length)? file.length: x+128;
      byte [] cp = Arrays.copyOfRange(file, x, last);
      byte [] ciphertext = cipher.doFinal(cp);
      Files.write(Paths.get("message.add-msg"), ciphertext, StandardOpenOption.APPEND);
    }
  }
  
  public static byte[] AESdecrypt(byte[] digitalDigest, byte[] symkey) throws Exception{
     
    //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
      
    Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
    //Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
    SecretKeySpec key = new SecretKeySpec(symkey, "AES"); //Where the symmetric key is used 
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
      
    return cipher.doFinal(digitalDigest);
    //return new String(cipher.doFinal(cipherText));
  }
  //SHA256
  public static byte [] md(String f) throws Exception {
    BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    DigestInputStream in = new DigestInputStream(file, md);
    int i;
    byte[] buffer = new byte[BUFFER_SIZE];
    do {
      i = in.read(buffer, 0, BUFFER_SIZE);
    } while (i == BUFFER_SIZE);
    md = in.getMessageDigest();
    in.close();

    byte[] hash = md.digest();
    return hash;
  }
  
  public static void compareMessage(String f)throws Exception{
    byte[] newdd = Files.readAllBytes(Paths.get("message.dd")); 
    byte[] olddd = md(f);
    if (Arrays.equals(newdd,olddd)){
      System.out.println("\nAuthentication Check Passed");
    }else{
      System.out.println("\nAuthentication Check Failed");
    }
  }

  public static void saveStringToFile(String s, String fname) throws Exception{
    Files.write(Paths.get(fname), s.getBytes());
  }//end saveStringToFile

} //End Receiver 

	
