import java.io.FileOutputStream;
import java.security.*;

public class KeyGeneratorUtil {
    public static void generateAndSaveRSAKeys(String user) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        try (FileOutputStream pubOut = new FileOutputStream(user + "_public.key")) {
            pubOut.write(pair.getPublic().getEncoded());
        }
        try (FileOutputStream privOut = new FileOutputStream(user + "_private.key")) {
            privOut.write(pair.getPrivate().getEncoded());
        }
    }

    public static void main(String[] args) throws Exception {
        generateAndSaveRSAKeys("sender");
        generateAndSaveRSAKeys("receiver");
        System.out.println("RSA key pairs generated.");
    }
}

