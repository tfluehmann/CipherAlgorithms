import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Created by tgdflto1 on 24.03.17.
 */
public class CipherBenchmarks {

    static byte[] key8Bytes = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    }; // 64 Bit Key

    static byte[] key16Bytes = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    }; // 128 Bit Key

    public static void main(String[] args) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        //BC is the ID for the Bouncy Castle provider;
        if (Security.getProvider("BC") == null) {
            System.out.println("Bouncy Castle provider is NOT available");
        } else {
            System.out.println("Bouncy Castle provider is available");
        }

        String content = null;
        try {
            content = new String(Files.readAllBytes(Paths.get("/tmp/500MB.file")));
        } catch (IOException e) {
            e.printStackTrace();
        }
        startEncrypt("3DES", content);
        startEncrypt("DES", content);
        startEncrypt("AES_CBC", content);
        startEncrypt("AES_CTR", content);
    }

    private static String startEncrypt(String algorithm, String content) {
        System.out.println("Starting to encrypt " + algorithm);
        byte[] encrypted = null;
        long beforeEnc = System.currentTimeMillis();
        try {
            switch (algorithm) {
                case "AES_CTR":
                    encrypted = encrypt(key16Bytes, content, "AES/CTR/PKCS5Padding", "AES", 16);
                    break;
                case "AES_CBC":
                    encrypted = encrypt(key16Bytes, content, "AES/CBC/PKCS5Padding", "AES", 16);
                    break;
                case "3DES":
                    encrypted = encrypt(key16Bytes, content, "DESede/CBC/PKCS5Padding", "DESede", 8);
                    break;
                case "DES":
                    encrypted = encrypt(key8Bytes, content, "DES/CBC/PKCS5Padding", "DES", 8);
                    break;
                default:
                    System.out.println("Unrecognized Algorithm");
                    System.exit(0);
            }
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | IllegalBlockSizeException |
                BadPaddingException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
        long afterEnc = System.currentTimeMillis();
        System.out.println(algorithm + " took " + (afterEnc - beforeEnc) / 1000 + " seconds");

        byte[] encryptedValue = Base64.encode(encrypted);
        return new String(encryptedValue);
    }

    //DES-CBC, 3DES-CBC, AES-128-CBC and AES-128-CTR
    private static byte[] encrypt(byte[] key16Bytes, String content, String algorithmDefinition, String keyType, int ivSize) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher desCipher = Cipher.getInstance(algorithmDefinition);
        SecretKey keySpec = new SecretKeySpec(key16Bytes, keyType);
        IvParameterSpec iv = new IvParameterSpec(new byte[ivSize]);
        desCipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        return desCipher.doFinal(content.getBytes());
    }
}