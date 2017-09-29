import java.security.*;
import java.io.*;
import java.security.spec.*;
import java.util.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

public class KeyGen{
  
  private final static SecureRandom random = new SecureRandom();
  
  //Public and Private Keys - X for sender, Y for Receiver
  private final static String X_PUBLIC_KEY_FILE = "XPublic.key";
  private final static String Y_PUBLIC_KEY_FILE = "YPublic.key";
  
  private final static String X_PRIVATE_KEY_FILE = "XPrivate.key";
  private final static String Y_PRIVATE_KEY_FILE = "YPrivate.key";
  
  private final static String SYMMETRIC_KEY_FILE= "symmetric.key";
  
  
  public static void main (String[] args) throws Exception{
    generateKeys();
  }

  private static void generateKeys() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
    //Generate a pair of keys
    SecureRandom random = new SecureRandom();
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(1024, random);  //1024: key size in bits
    KeyPair pair = generator.generateKeyPair();
    Key pubKey = pair.getPublic();
    Key privKey = pair.getPrivate();

    //get the parameters of the keys: modulus and exponet
    KeyFactory factory = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec pubKSpec = factory.getKeySpec(pubKey, 
        RSAPublicKeySpec.class);
    RSAPrivateKeySpec privKSpec = factory.getKeySpec(privKey, 
        RSAPrivateKeySpec.class);

    //save the parameters of the keys to the files
    saveToFile(X_PUBLIC_KEY_FILE, pubKSpec.getModulus(), 
        pubKSpec.getPublicExponent());
    saveToFile(X_PRIVATE_KEY_FILE, privKSpec.getModulus(), 
        privKSpec.getPrivateExponent());
  
    //Do the same as above for the next pair of keys
    pair = generator.generateKeyPair();
    pubKey = pair.getPublic();
    privKey = pair.getPrivate();

    pubKSpec = factory.getKeySpec(pubKey, 
        RSAPublicKeySpec.class);
    privKSpec = factory.getKeySpec(privKey, 
        RSAPrivateKeySpec.class);

    saveToFile(Y_PUBLIC_KEY_FILE, pubKSpec.getModulus(), 
        pubKSpec.getPublicExponent());
    saveToFile(Y_PRIVATE_KEY_FILE, privKSpec.getModulus(), 
        privKSpec.getPrivateExponent());

    Scanner scan = new Scanner(System.in);
    byte[] sym;
    do{
      System.out.print("Enter the 16 character string for the symmetric key: ");
      sym = scan.nextLine().getBytes("UTF-8");
    } while(sym.length != 16);
    Files.write(Paths.get(SYMMETRIC_KEY_FILE), sym);
  }

  //save the prameters of the public and private keys to file
  public static void saveToFile(String fileName,
    BigInteger mod, BigInteger exp) throws IOException {

    ObjectOutputStream oout = new ObjectOutputStream(
      new BufferedOutputStream(new FileOutputStream(fileName)));

    try {
      oout.writeObject(mod);
      oout.writeObject(exp);
    } catch (Exception e) {
      throw new IOException("Unexpected error", e);
    } finally {
      oout.close();
    }
  }
}
