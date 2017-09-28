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

public class Sender {
  static int BUFFER_SIZE = 32*1024;
  static String IV = "AAAAAAAAAAAAAAAA";
  public static void main (String[] args) throws Exception {
    Scanner scan = new Scanner(System.in);
    PublicKey pubKeyY = Readers.readPubKeyFromFile(Readers.Y_PUB_FILE_NAME);
    byte[] symkey = Readers.readSymKeyFromFile(Readers.SYM_KEY_FILE_NAME);
    System.out.print("Input the name of the message file: ");
    String fname = scan.nextLine();
    byte[] messageDigest = md(fname);
    saveStringToFile(new String(messageDigest), "message.dd");

    byte[] aesEncry = AESencrypt(messageDigest, symkey);
    
    System.out.println("AES-EN(SHA256(m)): ");
    for(int i = 0; i < aesEncry.length; i++){
      System.out.print(String.format("%2X ", aesEncry[i]));
      if(i == 15) System.out.print("\n");
    }

    Files.write(Paths.get("message.add-msg"), aesEncry);
    Files.write(Paths.get("message.add-msg"), Files.readAllBytes(Paths.get(fname)), StandardOpenOption.APPEND );
  }

  public static void saveStringToFile(String s, String fname) throws Exception{
    Files.write(Paths.get(fname), s.getBytes());
  }

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

    System.out.println("SHA256(M):");
    for (int k=0, j=0; k<hash.length; k++, j++) {
      System.out.format("%2X ", new Byte(hash[k])) ;
      if (j >= 15) {
        System.out.println("");
        j=-1;
      }
    }
    System.out.println("");    
    return hash;
  }
  public static byte[] AESencrypt(byte [] plaintext, byte[] symkey) throws Exception {

    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
    //Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
    //Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
    SecretKeySpec key = new SecretKeySpec(symkey, "AES");
    cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
    return cipher.doFinal(plaintext);
  }

}
