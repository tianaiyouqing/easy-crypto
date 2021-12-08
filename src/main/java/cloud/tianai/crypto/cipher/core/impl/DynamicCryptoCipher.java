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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
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
    private Integer encryptType;
    @Setter
    @Getter
    private Integer defaultDecryptType;
    @Getter
    private Map<Integer, Function<SimpleCryptoCipher, CryptoCipher>> dynamicCryptoCipherCreatorMap = new HashMap<>(8);

    public DynamicCryptoCipher(Cipher cipher, int model) {
        this(cipher, model, "AES", -1);
    }

    public DynamicCryptoCipher(Cipher cipher, int model, String encryptType, Integer defaultDecryptType) {
        super(cipher, model);
        this.encryptType = encryptType.hashCode();
        this.defaultDecryptType = defaultDecryptType;
        init();
    }

    private void init() {
        dynamicCryptoCipherCreatorMap.put("AES".hashCode(), c -> new AesCryptoCipher(c.getCipher(), c.getModel(), false, 1));
        dynamicCryptoCipherCreatorMap.put("SM4".hashCode(), c -> new Sm4CryptoCipher(c.getCipher(), c.getModel(), false, 2));
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

    public CryptoCipher requiredGetCurrentCryptoCipher() {
        if (currentCryptoCipher == null) {
            throw new IllegalArgumentException("没有读取到 currentCryptoCipher");
        }
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

    @SneakyThrows
    protected CryptoCipher getCurrentCryptoCipherIfNecessary(CipherInputStream source) {
        if (currentCryptoCipher == null) {
            Integer type;
            if (Cipher.DECRYPT_MODE == getModel()) {
                // 解密,匹配对应的算法
                DataInputStream dataInputStream = new DataInputStream(source.getDelegateStream());
                type = dataInputStream.readInt();
            } else {
                type = encryptType;
            }
            this.currentCryptoCipher = doGetCurrentCryptoCipher(type, true);
            if (currentCryptoCipher == null) {
                throw new CryptoCipherException("不支持的加密版本:" + type);
            }
        }
        return currentCryptoCipher;
    }

    @SneakyThrows
    protected CryptoCipher getCurrentCryptoCipherIfNecessary(CipherOutputStream source) {
        if (currentCryptoCipher == null) {
            Integer type;
            if (Cipher.DECRYPT_MODE == getModel()) {
                // 解密,匹配对应的算法
                // 暂时不支持
                throw new IllegalStateException("OutputStream not support decrypt");
            } else {
                type = encryptType;
            }
            this.currentCryptoCipher = doGetCurrentCryptoCipher(type, false);
            if (currentCryptoCipher == null) {
                throw new CryptoCipherException("不支持的加密版本:" + type);
            }
        }
        return currentCryptoCipher;

    }


    @Override
    @SneakyThrows
    public byte[] start(CipherInputStream source) {
        return getCurrentCryptoCipherIfNecessary(source).start(source);
    }


    @Override
    public byte[] start(byte[] b, int off, int len) {
        return null;
    }


    @Override
    public byte[] end() throws IllegalBlockSizeException, BadPaddingException {
        return requiredGetCurrentCryptoCipher().end();
    }

    @Override
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        byte[] bytes = beforeUpdate(input, inputOffset, inputLen);
        return requiredGetCurrentCryptoCipher().update(input, inputOffset, inputLen);
    }

    @SneakyThrows
    private byte[] beforeUpdate(byte[] input, int inputOffset, int inputLen) {
        if (Cipher.DECRYPT_MODE == getModel()) {
            // 解密,匹配对应的算法
            ByteArrayInputStream inputStream = new ByteArrayInputStream(input, inputOffset, inputLen);
            DataInputStream dataInputStream = new DataInputStream(inputStream);
            int type = dataInputStream.readInt();
        } else {
            // 把加密类型加在头信息上
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream(4);
            new DataOutputStream(outputStream).writeInt(encryptType);
            return outputStream.toByteArray();
        }
    }


    @Override
    public CryptoCipher recreate() {
        return requiredGetCurrentCryptoCipher().recreate();
    }

}
