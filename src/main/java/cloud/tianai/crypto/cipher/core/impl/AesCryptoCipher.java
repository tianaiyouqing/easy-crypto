package cloud.tianai.crypto.cipher.core.impl;

import cloud.tianai.crypto.cipher.core.AbstractCryptoCipher;
import cloud.tianai.crypto.cipher.core.CryptoCipher;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.security.SecureRandom;

/**
 * @Author: 天爱有情
 * @date 2020/9/14 14:55
 * @Description 底层加密算法为 AES ， 外层算法为自定义的算法框架
 * <p>
 * 算法流的格式
 * +---------+-----------+----------+---------+--------+------+
 * | version | cekLength | ivLength | cekData | ivData | data |
 * +---------+-----------+----------+---------+--------+------+
 */
@Slf4j
public class AesCryptoCipher extends AbstractCryptoCipher {

    public static final String CONTENT_CIPHER_ALGORITHM = "AES/CTR/NoPadding";
    public static final String KEY_GENERATOR_ALGORITHM = "AES";
    public static final int KEY_LENGTH_IN_BITS = 256;
    public static final int CIPHER_IV_LENGTH = 16;
    public static final int VERSION_V1 = 1;

    private static final SecureRandom RANDOM = new SecureRandom();

    @SneakyThrows
    public AesCryptoCipher(Cipher cipher, int model) {
        super(cipher, model);
    }

    @Override
    public String getAlgorithm() {
        return KEY_GENERATOR_ALGORITHM;
    }

    @Override
    public String getContentCipherAlgorithm() {
        return CONTENT_CIPHER_ALGORITHM;
    }

    @Override
    public int getKeyLength() {
        return KEY_LENGTH_IN_BITS;
    }

    @Override
    public int getIvLength() {
        return CIPHER_IV_LENGTH;
    }

    @Override
    public int getVersion() {
        return VERSION_V1;
    }

    @Override
    protected SecureRandom getRandom() {
        return RANDOM;
    }

    @Override
    public CryptoCipher recreate() {
        return new AesCryptoCipher(getCipher(), getModel());
    }
}
