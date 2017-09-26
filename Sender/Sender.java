import java.security.*;
import java.util.*;
import java.security.spec.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Files;

public class Sender {
  static int BUFFER_SIZE = 32*1024;

  public static void main (String[] args) throws Exception {
    Scanner scan = new Scanner(System.in);
    PublicKey pubKeyY = Readers.readPubKeyFromFile(Readers.Y_PUB_FILE_NAME);
    byte[] symkey = Readers.readSymKeyFromFile(Readers.SYM_KEY_FILE_NAME);
    System.out.print("Input the name of the message file: ");
    String fname = scan.nextLine();
    md(fname);
  }


 public static String md(String f) throws Exception {
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

    System.out.println("digit digest (hash value):");
    for (int k=0, j=0; k<hash.length; k++, j++) {
      System.out.format("%2X ", new Byte(hash[k])) ;
      if (j >= 15) {
        System.out.println("");
        j=-1;
      }
    }
    System.out.println("");    

    return new String(hash);
  }
}
