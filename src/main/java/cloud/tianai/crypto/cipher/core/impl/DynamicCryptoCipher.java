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
import java.io.DataInputStream;
import java.io.InputStream;
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
        dynamicCryptoCipherCreatorMap.put(1, c -> new AesCryptoCipher(c.getCipher(), c.getModel(), true, 1));
        dynamicCryptoCipherCreatorMap.put(2, c -> new Sm4CryptoCipher(c.getCipher(), c.getModel(), true, 2));
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

    public CryptoCipher getCurrentCryptoCipherOrElseThrow() {
        if (currentCryptoCipher == null) {
            throw new IllegalArgumentException("没有读取到 currentCryptoCipher");
        }
        return currentCryptoCipher;
    }

    protected CryptoCipher createCryptoCipher(int version, Integer defaultDecryptType) {
        Function<SimpleCryptoCipher, CryptoCipher> creator = dynamicCryptoCipherCreatorMap.get(version);
        if (creator != null) {
            return creator.apply(this);
        }
        if (defaultDecryptType != null) {
            return createCryptoCipher(defaultDecryptType, null);
        }
        return null;
    }

    @SneakyThrows
    protected CryptoCipher createCryptoCipherIfAbsent(InputStream source) {
        if (currentCryptoCipher == null) {
            Integer type;
            if (Cipher.DECRYPT_MODE == getModel()) {
                // 解密,匹配对应的算法
                if (source instanceof CipherInputStream) {
                    source = ((CipherInputStream) source).getDelegateStream();
                }
                DataInputStream dataInputStream = new DataInputStream(source);
                type = dataInputStream.readInt();
            } else {
                type = defaultEncryptType;
            }
            this.currentCryptoCipher = createCryptoCipher(type, defaultDecryptType);
            if (currentCryptoCipher == null) {
                throw new CryptoCipherException("不支持的加密版本:" + type);
            }
        }
        return currentCryptoCipher;
    }

    @SneakyThrows
    protected CryptoCipher createCryptoCipherIfAbsent(byte[] bytes) {
        int useLength = 0;
        if (currentCryptoCipher == null) {
            Integer type;
            if (Cipher.DECRYPT_MODE == getModel()) {
                // 解密,匹配对应的算法
                // 暂时不支持
                DataInputStream dataInputStream = new DataInputStream(new ByteArrayInputStream(bytes));
                type = dataInputStream.readInt();
                throw new IllegalStateException("OutputStream not support decrypt");
            } else {
                type = defaultEncryptType;
            }
            this.currentCryptoCipher = createCryptoCipher(type, null);
            if (currentCryptoCipher == null) {
                throw new CryptoCipherException("不支持的加密版本:" + type);
            }
        }
        return currentCryptoCipher;

    }


    @Override
    @SneakyThrows
    public byte[] start(CipherInputStream source) {
        return createCryptoCipherIfAbsent(source).start(source);
    }


    @Override
    public byte[] start(byte[] b, int off, int len) {
        byte[] bytes = new byte[len];
        System.arraycopy(b, off, bytes, 0, len);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
        byte[] start = createCryptoCipherIfAbsent(inputStream).start(b, off, len);
        if (start == null) {
            start = new byte[0];
        }
        int available = inputStream.available();
        if (available > 0) {
            byte[] update = getCurrentCryptoCipherOrElseThrow().update(bytes, bytes.length - available, available);
        }
        return start;
    }


    @Override
    public byte[] end() throws IllegalBlockSizeException, BadPaddingException {
        return getCurrentCryptoCipherOrElseThrow().end();
    }

    @Override
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        return getCurrentCryptoCipherOrElseThrow().update(input, inputOffset, inputLen);
    }

    @Override
    public byte[] earlyLoadingHeaderData(CipherInputStream source) {
        return createCryptoCipherIfAbsent(source).earlyLoadingHeaderData(source);
    }

    @Override
    public CryptoCipher recreate() {
        return getCurrentCryptoCipherOrElseThrow().recreate();
    }

}
