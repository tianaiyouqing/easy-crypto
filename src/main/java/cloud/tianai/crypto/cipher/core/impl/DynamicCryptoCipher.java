package cloud.tianai.crypto.cipher.core.impl;

import cloud.tianai.crypto.cipher.core.CryptoCipher;
import cloud.tianai.crypto.cipher.core.SimpleCryptoCipher;
import cloud.tianai.crypto.exception.CryptoCipherException;
import cloud.tianai.crypto.stream.CipherInputStream;
import cloud.tianai.crypto.stream.CipherOutputStream;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.DataInputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * @Author: 天爱有情
 * @date 2021/12/6 17:57
 * @Description 动态匹配底层算法加解密
 */
public class DynamicCryptoCipher extends SimpleCryptoCipher {

    private CryptoCipher currentCryptoCipher;
    @Setter
    @Getter
    private Integer defaultEncryptType;
    @Setter
    @Getter
    private Integer defaultDecryptType;
    @Getter
    private Map<Integer, Function<SimpleCryptoCipher, CryptoCipher>> dynamicCryptoCipherCreatorMap = new HashMap<>(8);

    public DynamicCryptoCipher(Cipher cipher, int model) {
        this(cipher, model, 1, -1);
    }

    public DynamicCryptoCipher(Cipher cipher, int model, Integer defaultEncryptType, Integer defaultDecryptType) {
        super(cipher, model);
        this.defaultEncryptType = defaultEncryptType;
        this.defaultDecryptType = defaultDecryptType;
        init();
    }

    private void init() {
        dynamicCryptoCipherCreatorMap.put(1, c -> new AesCryptoCipher(c.getCipher(), c.getModel(), false, 1));
        dynamicCryptoCipherCreatorMap.put(2, c -> new Sm4CryptoCipher(c.getCipher(), c.getModel(), false, 2));
    }

    public void setCryptoCipherCreator(int type, Function<SimpleCryptoCipher, CryptoCipher> creator) {
        dynamicCryptoCipherCreatorMap.put(type, creator);
    }

    @Override
    public int getVersion() {
        return -1;
    }

    public CryptoCipher getCurrentCryptoCipher() {
        return currentCryptoCipher;
    }

    protected CryptoCipher doGetCurrentCryptoCipher(int version, boolean matchDefault) {
        Function<SimpleCryptoCipher, CryptoCipher> creator = dynamicCryptoCipherCreatorMap.get(version);
        if (creator != null) {
            return creator.apply(this);
        }
        if (defaultDecryptType != null && matchDefault) {
            return doGetCurrentCryptoCipher(defaultDecryptType, false);
        }
        return null;
    }

    @Override
    @SneakyThrows
    public byte[] start(CipherInputStream source) {
        if (currentCryptoCipher != null) {
            return currentCryptoCipher.start(source);
        }
        Integer type;
        if (Cipher.DECRYPT_MODE == getModel()) {
            // 解密,匹配对应的算法
            DataInputStream dataInputStream = new DataInputStream(source.getDelegateStream());
            type = dataInputStream.readInt();
        } else {
            type = defaultEncryptType;
        }
        this.currentCryptoCipher = doGetCurrentCryptoCipher(type, true);
        if (currentCryptoCipher == null) {
            throw new CryptoCipherException("不支持的加密版本:" + type);
        }
        return currentCryptoCipher.start(source);
    }

    @Override
    public byte[] start(CipherOutputStream source) {
        if (currentCryptoCipher != null) {
            return currentCryptoCipher.start(source);
        }
        Integer type;
        if (Cipher.DECRYPT_MODE == getModel()) {
            // 解密,匹配对应的算法
            // 暂时不支持
            throw new IllegalStateException("OutputStream not support decrypt");
        } else {
            type = defaultEncryptType;
        }
        this.currentCryptoCipher = doGetCurrentCryptoCipher(type, false);
        if (currentCryptoCipher == null) {
            throw new CryptoCipherException("不支持的加密版本:" + type);
        }
        return currentCryptoCipher.start(source);
    }


    @Override
    public byte[] end() throws IllegalBlockSizeException, BadPaddingException {
        return currentCryptoCipher.end();
    }

    @Override
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        return currentCryptoCipher.update(input, inputOffset, inputLen);
    }

    @Override
    public byte[] earlyLoadingHeaderData(CipherInputStream source) {
        return currentCryptoCipher.earlyLoadingHeaderData(source);
    }

    @Override
    public CryptoCipher recreate() {
        return currentCryptoCipher.recreate();
    }

    @Override
    public byte[] earlyLoadingHeaderData(CipherOutputStream source) {
        return currentCryptoCipher.earlyLoadingHeaderData(source);
    }
}
