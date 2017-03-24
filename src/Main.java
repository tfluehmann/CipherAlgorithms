import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class Main {

    public final static int ARRAY_SIZE=256;
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Random rand = new Random();
        byte[] byteArray = new byte[ARRAY_SIZE];
        rand.nextBytes(byteArray);

        for(int i = 0; i < ARRAY_SIZE; i++)
            System.out.println(byteArray[i]);

        System.out.println("\n\n\n\n");


        byte[] newByteArray = new byte[ARRAY_SIZE];
        SecureRandom sha1Prng = SecureRandom.getInstance("SHA1PRNG");
        sha1Prng.nextBytes(newByteArray);
        for(int i = 0; i < ARRAY_SIZE; i++)
            System.out.println(newByteArray[i]);
    }
}
