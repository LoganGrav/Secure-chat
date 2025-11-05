import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Sender {
    public static void main(String[] args) throws Exception {
        String message = Files.readString(Path.of("message.txt"));

        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();

        // Encrypt message with AES
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedMsg = aesCipher.doFinal(message.getBytes());

        // Load receiver's public RSA key
        byte[] pubKeyBytes = Files.readAllBytes(Path.of("receiver_public.key"));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey receiverPublicKey = keyFactory.generatePublic(keySpec);

        // Encrypt AES key with RSA
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Generate MAC
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(aesKey.getEncoded(), "HmacSHA256"));
        byte[] macBytes = mac.doFinal(encryptedMsg);

        // Write to Transmitted_Data
        try (FileOutputStream out = new FileOutputStream("Transmitted_Data.txt")) {
            out.write("AES key: ".getBytes());
            out.write(Base64.getEncoder().encode(encryptedAesKey));
            out.write("\n".getBytes());
            out.write("Ciphertext: ".getBytes());
            out.write(Base64.getEncoder().encode(encryptedMsg));
            out.write("\n".getBytes());
            out.write("MAC: ".getBytes());
            out.write(Base64.getEncoder().encode(macBytes));
        }
        System.out.println("Data sent.");
    }
}
