package cloud.tianai.crypto.cipher;

import cloud.tianai.crypto.cipher.core.impl.DynamicCryptoCipher;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * @Author: 天爱有情
 * @Date 2020/9/2 15:28
 * @Description 基于 3des算法实现想密码 加解密,
 */
public class CryptoCipherBuilder {

    public static final String DES_CIPHER_ALGORITHM = "desede/CBC/PKCS5Padding";
    public static final String DES_KEY_ALGORITHM = "desede";
    private final static byte[] KEY_IV = {0, 0, 0, 0, 0, 0, 0, 0};


    public static final String AES_CIPHER_ALGORITHM = "AES/CTR/NoPadding";
    public static final String AES_KEY_ALGORITHM = "AES";

    public static final String RSA_CIPHER_ALGORITHM = "RSA/NONE/PKCS1Padding";

    public static final boolean ENCRYPT = true;
    public static final boolean DECRYPT = false;


    /**
     * 3des 算法
     *
     * @param secretKey 秘钥
     * @param encrypt   加密true 解密false
     * @return CryptoCipher
     */
    @SneakyThrows
    public static DynamicCryptoCipher buildDes3Crypt(String secretKey, boolean encrypt) {
        if (StringUtils.isBlank(secretKey) || secretKey.length() != 24) {
            throw new IllegalArgumentException("3des加密key必须为24位");
        }
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES_KEY_ALGORITHM);
        DESedeKeySpec spec = new DESedeKeySpec(secretKey.getBytes());
        Key desKey = keyFactory.generateSecret(spec);
        IvParameterSpec ips = new IvParameterSpec(KEY_IV);
        Cipher cipher = Cipher.getInstance(DES_CIPHER_ALGORITHM);
        int model = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        cipher.init(model, desKey, ips);
        return new DynamicCryptoCipher(cipher, model);
    }

    /**
     * RSA 算法
     *
     * @param key     公钥、私钥
     * @param encrypt 加密true 解密false
     * @return CryptoCipher
     */
    @SneakyThrows
    public static DynamicCryptoCipher buildRsaCrypt(Key key, boolean encrypt) {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);
        int model = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        cipher.init(model, key);
        return new DynamicCryptoCipher(cipher, model);
    }


    /**
     * AES 算法
     *
     * @param secretKey 秘钥
     * @param encrypt   加密true 解密false
     * @return CryptoCipher
     */
    @SneakyThrows
    public static DynamicCryptoCipher buildAesCrypt(String secretKey, boolean encrypt) {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        SecretKeySpec keyspec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), AES_KEY_ALGORITHM);
        int model = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        cipher.init(model, keyspec);
        return new DynamicCryptoCipher(cipher, model);
    }
}
