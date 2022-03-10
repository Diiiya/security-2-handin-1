package encryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Extensions {
    public static SecretKey defineKey(byte[] keyBytes) {
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32)
        {
            throw new IllegalArgumentException("keyBytes wrong length for AES key");
        }
        return new SecretKeySpec(keyBytes, "AES");
    }
}
