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

    ByteArrayOutputStream beforeOutputData = new ByteArrayOutputStream();
    ByteArrayOutputStream beforeInputData = new ByteArrayOutputStream();

    @SneakyThrows
    public AbstractCryptoCipher(Cipher cipher, int model) {
        super(cipher, model);

    }

    @Override
    public void writeBeforeData(byte[] input, int inputOffset, int inputLen) {
        beforeOutputData.write(input, inputOffset, inputLen);
    }

    @Override
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        // 判断是否已经初始化
        if (internalCipher != null) {
            return internalCipher.update(input, inputOffset, inputLen);
        }
        // 记录更新来的数据
        beforeInputData.write(input, inputOffset, inputLen);
        byte[] headerBytes = beforeInputData.toByteArray();
        // 尝试初始化
        int useLength = tryInitCipher(headerBytes);
        // 如果初始化失败，返回 0
        if (internalCipher == null) {
            return new byte[0];
        }
        // 如果初始化成功
        if (useLength == headerBytes.length) {
            return new byte[0];
        }
        if (beforeOutputData.size() > 0) {
            byte[] headerData = beforeOutputData.toByteArray();
            byte[] update = update(headerBytes, useLength, headerBytes.length - useLength);
            byte[] result = new byte[beforeOutputData.size() + update.length];
            System.arraycopy(headerData, 0, result, 0, headerData.length);
            System.arraycopy(update, 0, result, headerData.length, update.length);
            return result;
        }
        return update(headerBytes, useLength, headerBytes.length - useLength);
    }

    @SneakyThrows
    private int tryInitCipher(byte[] headerBytes) {
        if (Cipher.ENCRYPT_MODE == getModel()) {
            // 加密
            initEncryptCipher();
            beforeOutputData.write(getEncryptHeaderBytes());
            return 0;
        }
        // 尝试读取一下解密数据
        int result = tryInitEncryptData(headerBytes);
        if (encryptData != null && internalCipher == null) {
            // 初始化解密
            initDecryptCipher();
        }
        return result;
    }

    @SneakyThrows
    private int tryInitEncryptData(byte[] headerBytes) {
        // 解密文件
        ByteArrayInputStream inputStream = new ByteArrayInputStream(headerBytes);
        DataInputStream dataInputStream = new DataInputStream(inputStream);
        // 版本号
        boolean matchVersion = skipCheckVersion();
        Integer version = null;
        if (!matchVersion) {
            version = dataInputStream.readInt();
            if (getVersion() != version) {
                // 如果不是 v1 版本，那就抛个异常
                throw new CryptoCipherException("不支持的加密版本:" + version);
            }
        }
        int encryptIvLength = dataInputStream.readInt();
        int encryptCekLength = dataInputStream.readInt();
        byte[] encryptedIV = new byte[encryptIvLength];
        byte[] encryptedCEK = new byte[encryptCekLength];

        try {
            dataInputStream.readFully(encryptedIV);
        } catch (EOFException e) {
            // 数据不够，读取失败
            return 0;
        }

        try {
            dataInputStream.readFully(encryptedCEK);
        } catch (IOException e) {
            // 数据不够，读取失败
            return 0;
        }
        encryptData = new EncryptData(encryptedIV, encryptedCEK);

        if (log.isDebugEnabled()) {
            log.debug("init AES Decrypt Cipher \r\n version:{}\r\n IV:{}, \r\n CEK:{},\r\n encryptIV:{}, \r\n encryptCEK:{}",
                    version,
                    Arrays.toString(this.iv),
                    Arrays.toString(this.secretKey.getEncoded()),
                    Arrays.toString(encryptedIV),
                    Arrays.toString(encryptedCEK));
        }
        return headerBytes.length - inputStream.available();
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
        return getHeaderData(source.getDelegateStream());
    }

    @Override
    public byte[] start(CipherInputStream source) {
        return null;
//        return getHeaderData(source.getDelegateStream());
    }


    @Override
    public byte[] start(byte[] b, int off, int len) {
        return null;
//        return getHeaderData(source.getDelegateStream());
    }

    @SneakyThrows
    public byte[] getHeaderData(InputStream source) {
        if (beforeOutputData.size() < 1) {
            if (Cipher.ENCRYPT_MODE == getModel()) {
                // 加密
                initEncryptCipher();
                beforeOutputData.write(getEncryptHeaderBytes());
            } else {
                // 解密
                beforeOutputData.write(decrypt(source));
            }
        }
        return beforeOutputData.toByteArray();
    }


    @SneakyThrows
    public byte[] getHeaderData(OutputStream source) {
        initEncryptCipher();
        beforeOutputData.write(getEncryptHeaderBytes());
        return beforeOutputData.toByteArray();
    }


    @SneakyThrows
    protected byte[] decrypt(InputStream source) {
        // 解密文件
        DataInputStream dataInputStream = new DataInputStream(source);
        // 版本号
        boolean matchVersion = skipCheckVersion();
        Integer version = null;
        if (!matchVersion) {
            version = dataInputStream.readInt();
            if (getVersion() != version) {
                // 如果不是 v1 版本，那就抛个异常
                throw new CryptoCipherException("不支持的加密版本:" + version);
            }
        }
        int encryptIvLength = dataInputStream.readInt();
        int encryptCekLength = dataInputStream.readInt();
        byte[] encryptedIV = new byte[encryptIvLength];
        byte[] encryptedCEK = new byte[encryptCekLength];

        try {
            dataInputStream.readFully(encryptedIV);
        } catch (EOFException e) {
            throw new IOException("读取 IV 失败， 期望读取的IV长度为:" + encryptIvLength);
        }

        try {
            dataInputStream.readFully(encryptedCEK);
        } catch (IOException e) {
            throw new IOException("读取 cek 失败， 期望读取的cek长度为:" + encryptCekLength);
        }
        encryptData = new EncryptData(encryptedIV, encryptedCEK);
        // 初始化解密
        initDecryptCipher();

        if (log.isDebugEnabled()) {
            log.debug("init AES Decrypt Cipher \r\n version:{}\r\n IV:{}, \r\n CEK:{},\r\n encryptIV:{}, \r\n encryptCEK:{}",
                    version,
                    Arrays.toString(this.iv),
                    Arrays.toString(this.secretKey.getEncoded()),
                    Arrays.toString(encryptedIV),
                    Arrays.toString(encryptedCEK));
        }
        return null;
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
    protected void initDecryptCipher() {
        // 解密向量
        byte[] encryptedIV = encryptData.getEncryptedIV();
        byte[] encryptedCEK = encryptData.getEncryptedCEK();
        this.iv = getCipher().doFinal(encryptedIV);
        byte[] cekBytes = getCipher().doFinal(encryptedCEK);
        this.secretKey = new SecretKeySpec(cekBytes, getAlgorithm());
        this.internalCipher = createCryptoCipherFromContentMaterial(this.iv, this.secretKey, model);
    }


    @SneakyThrows
    protected void initEncryptCipher() {
        this.iv = generateIV();
        this.secretKey = generateCEK();
        this.internalCipher = createCryptoCipherFromContentMaterial(this.iv, this.secretKey, model);
        encryptData = new EncryptData();
        encryptData.setEncryptedIV(cipher.doFinal(this.iv));
        encryptData.setEncryptedCEK(cipher.doFinal(this.secretKey.getEncoded()));
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
            log.debug("init AES Encrypt Cipher \r\n version:{}\r\n IV:{}, \r\n CEK:{},\r\n encryptIV:{}, \r\n encryptCEK:{}",
                    getVersion(),
                    Arrays.toString(this.iv),
                    Arrays.toString(this.secretKey.getEncoded()),
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
