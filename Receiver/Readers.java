import java.security.*;
import java.util.*;
import java.security.spec.*;
import java.io.*;
import java.math.*;
import java.nio.file.Files;
import java.nio.file.Paths;


public class Readers{
  public static final String X_PUB_FILE_NAME = "XPublic.key";
  public static final String X_PRIV_FILE_NAME = "XPrivate.key";
  public static final String Y_PUB_FILE_NAME = "YPublic.key";
  public static final String Y_PRIV_FILE_NAME = "YPrivate.key";
  public static final String SYM_KEY_FILE_NAME = "symmetric.key";

  
  public static void main (String[] args)throws Exception {
    PublicKey pubKeyX = readPubKeyFromFile(X_PUB_FILE_NAME);
    PrivateKey privKeyX = readPrivKeyFromFile(X_PRIV_FILE_NAME);
    
    PublicKey pubKeyY = readPubKeyFromFile(Y_PUB_FILE_NAME);
    PrivateKey privKeyY = readPrivKeyFromFile(Y_PRIV_FILE_NAME);
    byte[] symkey = readSymKeyFromFile(SYM_KEY_FILE_NAME);
    System.out.println("Symmetric Key(decimal): " + Arrays.toString(symkey));
  }

  //read key parameters from a file and generate the public key 
  public static PublicKey readPubKeyFromFile(String keyFileName) 
      throws IOException {
    InputStream in = 
        new FileInputStream(keyFileName);
    ObjectInputStream oin =
        new ObjectInputStream(new BufferedInputStream(in));

    try {
      BigInteger m = (BigInteger) oin.readObject();
      BigInteger e = (BigInteger) oin.readObject();


      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
      KeyFactory factory = KeyFactory.getInstance("RSA");
      PublicKey key = factory.generatePublic(keySpec);

      return key;
    } catch (Exception e) {
      throw new RuntimeException("Spurious serialisation error", e);
    } finally {
      oin.close();
    }
  }


  //read key parameters from a file and generate the public key 
  public static PrivateKey readPrivKeyFromFile(String keyFileName) 
      throws IOException {

    InputStream in = 
        new FileInputStream(keyFileName);
    ObjectInputStream oin =
        new ObjectInputStream(new BufferedInputStream(in));

    try {
      BigInteger m = (BigInteger) oin.readObject();
      BigInteger e = (BigInteger) oin.readObject();


      RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
      KeyFactory factory = KeyFactory.getInstance("RSA");
      PrivateKey key = factory.generatePrivate(keySpec);

      return key;
    } catch (Exception e) {
      throw new RuntimeException("Spurious serialisation error", e);
    } finally {
      oin.close();
    }
  }
  public static byte[] readSymKeyFromFile(String keyFileName) throws Exception{
    return Files.readAllBytes(Paths.get(keyFileName));   
  }
}
