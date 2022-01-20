package cloud.tianai.crypto.cipher.core;

import cloud.tianai.crypto.exception.CryptoCipherException;
import cloud.tianai.crypto.stream.CipherInputStream;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @Author: 天爱有情
 * @date 2020/9/14 14:55
 * @Description 抽象的底层加密算法，提取公共加密逻辑， 外层算法为自定义的算法框架
 * <p>
 * 算法流的格式
 * +---------+-----------+----------+---------+--------+------+
 * | version | cekLength | ivLength | cekData | ivData | data |
 * +---------+-----------+----------+---------+--------+------+
 */
@Slf4j
public abstract class AbstractCryptoCipher extends SimpleCryptoCipher {
    byte[] iv;
    SecretKey secretKey;
    EncryptData encryptData;
    Cipher internalCipher;
    byte[] headerData;
    /** 帮助初始化 internalCipher， internalCipher初始化完后清除该数据.*/
    private ByteArrayOutputStream beforeInputData = new ByteArrayOutputStream();

    @SneakyThrows
    public AbstractCryptoCipher(Cipher cipher, int model) {
        super(cipher, model);

    }

    @Override
    @SneakyThrows(IOException.class)
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        // 判断是否已经初始化
        if (internalCipher != null) {
            return internalCipher.update(input, inputOffset, inputLen);
        }
        // 记录更新来的数据
        beforeInputData.write(input, inputOffset, inputLen);
        byte[] headerBytes = beforeInputData.toByteArray();
        ByteArrayInputStream headerInputStream = new ByteArrayInputStream(headerBytes);
        // 尝试初始化
        tryInitCipher(headerInputStream);
        // 如果初始化失败，返回 0
        if (internalCipher == null) {
            return new byte[0];
        }
        // internalCipher初始化完后清除掉 beforeInputData
        beforeInputData.close();
        int useLength = headerBytes.length - headerInputStream.available();
        // 如果初始化成功
        if (useLength == headerBytes.length) {
            return new byte[0];
        }
        if (headerData != null) {
            byte[] update = update(headerBytes, useLength, headerBytes.length - useLength);
            byte[] result = new byte[headerData.length + update.length];
            System.arraycopy(headerData, 0, result, 0, headerData.length);
            System.arraycopy(update, 0, result, headerData.length, update.length);
            // 用完就抛弃
            headerData = null;
            return result;
        }
        return update(headerBytes, useLength, headerBytes.length - useLength);
    }

    @SneakyThrows
    protected void tryInitCipher(InputStream inputStream) {
        if (Cipher.ENCRYPT_MODE == getModel()) {
            // 加密
            initEncryptCipher();
            headerData = getEncryptHeaderBytes();
        } else {
            // 尝试读取一下解密数据
            encryptData = tryGetEncryptData(inputStream);
            if (encryptData != null && internalCipher == null) {
                // 初始化解密
                cipher = createDecryptCipher();
                // 赋值
                this.internalCipher = cipher;
            }
        }
    }

    @SneakyThrows
    private EncryptData tryGetEncryptData(InputStream inputStream) {
        // 解密文件
        if (inputStream instanceof CipherInputStream) {
            inputStream = ((CipherInputStream) inputStream).getDelegateStream();
        }
        DataInputStream dataInputStream = new DataInputStream(inputStream);
        // 版本号
        boolean matchVersion = skipCheckVersion();
        Integer version = null;
        if (!matchVersion) {
            // 不至于第一个int都读不到吧... 233
            version = dataInputStream.readInt();
            if (getVersion() != version) {
                // 如果不是 v1 版本，那就抛个异常
                throw new CryptoCipherException("不支持的加密版本:" + version);
            }
        }
        byte[] encryptedIV;
        byte[] encryptedCEK;
        try {
            int encryptIvLength = dataInputStream.readInt();
            int encryptCekLength = dataInputStream.readInt();
            encryptedIV = new byte[encryptIvLength];
            encryptedCEK = new byte[encryptCekLength];
            dataInputStream.readFully(encryptedIV);
            dataInputStream.readFully(encryptedCEK);
        } catch (EOFException e) {
            // 数据不够，读取失败
            return null;
        }

        EncryptData encryptData = new EncryptData(encryptedIV, encryptedCEK);

        if (log.isDebugEnabled()) {
            log.debug("init AES Decrypt Cipher \r\n version:{}\r\n encryptIV:{}, \r\n encryptCEK:{}",
                    version,
                    Arrays.toString(encryptedIV),
                    Arrays.toString(encryptedCEK));
        }
        return encryptData;
    }

    @Override
    public byte[] end() throws IllegalBlockSizeException, BadPaddingException {
        if (internalCipher == null) {
            return new byte[0];
        }
        return internalCipher.doFinal();
    }

    @Override
    public byte[] earlyLoadingHeaderData(CipherInputStream source) {
        tryInitCipher(source);
        return headerData;
    }

    @Override
    public byte[] start(CipherInputStream source) {
        // inputStream的话进行预加载
        if (internalCipher == null) {
            tryInitCipher(source);
        }
        return headerData;
    }

    @Override
    public byte[] start(byte[] b, int off, int len) {
        return null;
//        return getHeaderData(source.getDelegateStream());
    }

    /**
     * 读取并匹配版本之前，返回true跳过匹配版本
     *
     * @return boolean
     */
    protected boolean skipCheckVersion() {
        return false;
    }


    @SneakyThrows
    protected Cipher createDecryptCipher() {
        // 解密向量
        byte[] encryptedIV = encryptData.getEncryptedIV();
        byte[] encryptedCEK = encryptData.getEncryptedCEK();
        this.iv = getCipher().doFinal(encryptedIV);
        byte[] cekBytes = getCipher().doFinal(encryptedCEK);
        this.secretKey = new SecretKeySpec(cekBytes, getAlgorithm());
        return createCryptoCipherFromContentMaterial(this.iv, this.secretKey, model);
    }


    @SneakyThrows
    protected Cipher initEncryptCipher() {
        this.iv = generateIV();
        this.secretKey = generateCEK();
        this.internalCipher = createCryptoCipherFromContentMaterial(this.iv, this.secretKey, model);
        encryptData = new EncryptData();
        encryptData.setEncryptedIV(cipher.doFinal(this.iv));
        encryptData.setEncryptedCEK(cipher.doFinal(this.secretKey.getEncoded()));
        return internalCipher;
    }

    @SneakyThrows
    protected byte[] getEncryptHeaderBytes() {
        byte[] encryptedCEK = encryptData.getEncryptedCEK();
        byte[] encryptedIV = encryptData.getEncryptedIV();
        int encryptCekLength = encryptedCEK.length;
        int encryptIvLength = encryptedIV.length;

        ByteArrayOutputStream output = new ByteArrayOutputStream(12 + encryptCekLength + encryptIvLength);
        DataOutputStream dataOutputStream = new DataOutputStream(output);

        // 版本号
        dataOutputStream.writeInt(getVersion());
        // 加密的IV 的长度
        dataOutputStream.writeInt(encryptedIV.length);
        // 加密的 cek的长度
        dataOutputStream.writeInt(encryptedCEK.length);
        // 加密的 IV 的内容
        dataOutputStream.write(encryptedIV);
        // 加密的 cek的内容
        dataOutputStream.write(encryptedCEK);

        if (log.isDebugEnabled()) {
            log.debug("init AES Encrypt Cipher \r\n encryptIV:{}, \r\n encryptCEK:{}",
                    Arrays.toString(encryptedIV),
                    Arrays.toString(encryptedCEK));
        }

        dataOutputStream.flush();
        dataOutputStream.close();
        return output.toByteArray();
    }

    @SneakyThrows
    public Cipher createCryptoCipherFromContentMaterial(byte[] iv, SecretKey cek, int cipherMode) {
        Cipher cipher;
        cipher = Cipher.getInstance(getContentCipherAlgorithm());
        cipher.init(cipherMode, cek, new IvParameterSpec(iv));
        return cipher;
    }

    protected SecretKey generateCEK() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(getAlgorithm());
            generator.init(getKeyLength(), getRandom());
            SecretKey secretKey;
            for (int retry = 0; retry < 9; retry++) {
                secretKey = generator.generateKey();
                if (secretKey.getEncoded()[0] != 0) {
                    return secretKey;
                }
            }
            throw new CryptoCipherException("Failed to generate secret key");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoCipherException("No such algorithm:" + getAlgorithm() + ", " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("AlibabaLowerCamelCaseVariableNaming")
    protected byte[] generateIV() {
        final byte[] iv = new byte[getIvLength()];
        getRandom().nextBytes(iv);
        for (int i = 8; i < 12; i++) {
            iv[i] = 0;
        }
        return iv;
    }


    @NoArgsConstructor
    @AllArgsConstructor
    @Data
    public static class EncryptData {
        byte[] encryptedIV;
        byte[] encryptedCEK;
    }

    protected SecureRandom getRandom() {
        return new SecureRandom();
    }

    public abstract String getAlgorithm();

    public abstract String getContentCipherAlgorithm();

    public abstract int getKeyLength();

    public abstract int getIvLength();
}
