import encryption.AESEncryptionECB;
import encryption.AESEncryptionGCM;
import encryption.Extensions;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.crypto.DataLengthException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {
    public static void main(String[] args) throws GeneralSecurityException {

        // String Encryption with AES in ECB mode
        String input = "Really secret stuff comes here.";
        byte[] bInput = input.getBytes();

        String key = "jDxESdRrcYKmSZi7IOW4lw==";
        byte[] bKey = key.getBytes();
        SecretKey aesKey = Extensions.defineKey(bKey);

        var encrypted = AESEncryptionECB.ecbEncrypt(aesKey, bInput);

        String str = new String(encrypted, StandardCharsets.UTF_8);
        System.out.println(str);

        byte[] decrypted = AESEncryptionECB.ecbDecrypt(aesKey,encrypted);
        System.out.println(new String(decrypted, StandardCharsets.UTF_8));

        // Image Encryption
        encryptImage(aesKey);
        decryptImage(aesKey);

        // AES encryption in GCM mode
        byte[] gcmBytes = "e6d4d9472cf9b7a92a652fc7e1f3b4124906cff47f42115d77d64709f2177503".getBytes();
        SecretKey gcmKey = Extensions.defineKey(gcmBytes);

        var text = "test string";
        byte[] bText = text.getBytes();
        var result = AESEncryptionGCM.gcmEncrypt(gcmKey,bText);
        var params = (AlgorithmParameters)Arrays.stream(result).findFirst().get();

        byte[] toDecrypt = "a2d21879269610eab7c16250b3b4bd81fc41b99738d7f8f2966ecd0bb2e5682a".getBytes();
        var decryptedGCM = AESEncryptionGCM.gcmDecrypt(gcmKey,params,toDecrypt);
        System.out.println(decryptedGCM);

    }

    private static void encryptImage(SecretKey key) {
        try {
            FileInputStream inputImage =
                    new FileInputStream(new File("screenshot.bmp"));
            FileOutputStream outputImage = new FileOutputStream(new File("encrypted.bmp"));

            byte[] inputImageByteArray = inputImage.readAllBytes();

            var headerBytes = Arrays.copyOfRange(inputImageByteArray, 0, 137);
            var bodyBytes = Arrays.copyOfRange(inputImageByteArray, 138, inputImageByteArray.length - 1);

            var encryptedBody = AESEncryptionECB.ecbEncrypt(key, bodyBytes);
            var encryptedImage = ArrayUtils.addAll(headerBytes,encryptedBody);
            FileUtils.writeByteArrayToFile(new File("encrypted.bmp"), encryptedImage);

        } catch (ShortBufferException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (DataLengthException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalStateException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void decryptImage(SecretKey key) {
        try {
            FileInputStream inputImage =
                    new FileInputStream(new File("encrypted.bmp"));
            FileOutputStream outputImage = new FileOutputStream(new File("encrypted.bmp"));

            byte[] inputImageByteArray = inputImage.readAllBytes();

            var headerBytes = Arrays.copyOfRange(inputImageByteArray, 0, 137);
            var bodyBytes = Arrays.copyOfRange(inputImageByteArray, 138, inputImageByteArray.length - 1);

            var decryptedBody = AESEncryptionECB.ecbDecrypt(key, bodyBytes);
            var decryptedImage = ArrayUtils.addAll(headerBytes,decryptedBody);
            FileUtils.writeByteArrayToFile(new File("decrypted.bmp"), decryptedImage);

        } catch (ShortBufferException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (DataLengthException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalStateException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
