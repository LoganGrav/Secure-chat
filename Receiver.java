import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Receiver {

    // Initialize all variables as class fields
    private static byte[] encryptedAesKey;  // Encrypted AES key (from the sender)
    private static byte[] encryptedMsg;     // Encrypted message
    private static byte[] receivedMac;      // Received MAC
    private static PrivateKey receiverPrivateKey;  // Receiver's private RSA key
    private static SecretKey aesKey;        // Decrypted AES key
    private static byte[] privKeyBytes;     // Private key bytes
    private static byte[] aesKeyBytes;      // Decrypted AES key bytes
    private static byte[] computedMac;      // Computed MAC

    public static void main(String[] args) throws Exception {
        readData();
        loadPrivateKey();
        decryptAESKey();
        verifyMAC();
        decryptMessage();
    }



    private static void readData() throws Exception {
        // Step 1, read data
        String[] lines = Files.readAllLines(Path.of("Transmitted_Data.txt")).toArray(String[]::new);  // Read all lines from file

        String aesKeyData = lines[0].split(":", 2)[1].trim();   //Reformat the data, remove headers
        String ciphertextData = lines[1].split(":", 2)[1].trim();
        String macData = lines[2].split(":", 2)[1].trim();

        encryptedAesKey = Base64.getDecoder().decode(aesKeyData);   // Line 1 = AES key
        encryptedMsg = Base64.getDecoder().decode(ciphertextData);  // Line 2 = Encrypted message
        receivedMac = Base64.getDecoder().decode(macData);          // Line 3 = MAC
    }



    private static void loadPrivateKey() throws Exception {
        // Step 2, load private key
        privKeyBytes = Files.readAllBytes(Path.of("receiver_private.key"));  // Read private key bytes
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyBytes);    // Create key spec
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  // Shoutout to stackoverflow
        receiverPrivateKey = keyFactory.generatePrivate(keySpec);   // Generate private key
    }



    private static void decryptAESKey() throws Exception {
        // Step 3, decrypt with private key
        Cipher rsaCipher = Cipher.getInstance("RSA");   // Get RSA cipher instance
        rsaCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);    // Initialize cipher with private key
        aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);   // Decrypt AES key
        aesKey = new SecretKeySpec(aesKeyBytes, "AES");  // Create AES key from decrypted bytes
    }



    private static void verifyMAC() throws Exception {
        // Step 4, verify MAC
        Mac mac = Mac.getInstance("HmacSHA256");    // Get HMAC instance with proper algorithm
        mac.init(new SecretKeySpec(aesKey.getEncoded(), "HmacSHA256"));  // Initialize MAC with AES key
        computedMac = mac.doFinal(encryptedMsg);    // Compute MAC for received message

        if (!MessageDigest.isEqual(receivedMac, computedMac)) { // If MACs match,
            System.out.println("Message authentication failed.");  // Print error message
        }
    }



    private static void decryptMessage() throws Exception {
        // Step 5, decrypt
        Cipher aesCipher = Cipher.getInstance("AES");   // Get AES cipher instance
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);    // Initialize cipher with AES key
        byte[] originalMsg = aesCipher.doFinal(encryptedMsg);   // Decrypt message
        System.out.println("Received message: " + new String(originalMsg)); // Print decrypted message
    }
}

