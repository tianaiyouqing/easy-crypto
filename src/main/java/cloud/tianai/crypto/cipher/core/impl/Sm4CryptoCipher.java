package cloud.tianai.crypto.cipher.core.impl;

import cloud.tianai.crypto.cipher.core.AbstractCryptoCipher;
import cloud.tianai.crypto.cipher.core.CryptoCipher;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.security.SecureRandom;

/**
 * @Author: 天爱有情
 * @date 2021/11/26 15:34
 * @Description 底层加密算法为 SM4 ， 外层算法为自定义的算法框架
 * 算法流的格式
 * +---------+-----------+----------+---------+--------+------+
 * | version | cekLength | ivLength | cekData | ivData | data |
 * +---------+-----------+----------+---------+--------+------+
 */
@Slf4j
public class Sm4CryptoCipher extends AbstractCryptoCipher {

    public static final String CONTENT_CIPHER_ALGORITHM = "SM4/CTR/NoPadding";
    public static final String KEY_GENERATOR_ALGORITHM = "SM4";
    public static final int KEY_LENGTH_IN_BITS = 128;
    public static final int CIPHER_IV_LENGTH = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    @Setter
    public int version = 1;
    boolean skipCheckVersion;

    @SneakyThrows
    public Sm4CryptoCipher(Cipher cipher, int model) {
        this(cipher, model, false);
    }

    @SneakyThrows
    public Sm4CryptoCipher(Cipher cipher, int model, boolean skipCheckVersion) {
        super(cipher, model);
        this.skipCheckVersion = skipCheckVersion;
    }

    @SneakyThrows
    public Sm4CryptoCipher(Cipher cipher, int model, boolean skipCheckVersion, int version) {
        super(cipher, model);
        this.skipCheckVersion = skipCheckVersion;
        this.version = version;
    }

    @Override
    protected boolean skipCheckVersion() {
        return skipCheckVersion;
    }

    @Override
    public CryptoCipher recreate() {
        return new Sm4CryptoCipher(getCipher(), getModel());
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
        return version;
    }
}
