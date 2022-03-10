package encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;

public class AESEncryptionGCM {

    public static Object[] gcmEncrypt(SecretKey key, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, Hex.decode("000102030405060708090a0b")));
        return new Object[] { cipher.getParameters(), cipher.doFinal(data), };
    }


    public static byte[] gcmDecrypt(SecretKey key, AlgorithmParameters gcmParameters, byte[] cipherText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameters);
        return cipher.doFinal(cipherText);
    }

}
