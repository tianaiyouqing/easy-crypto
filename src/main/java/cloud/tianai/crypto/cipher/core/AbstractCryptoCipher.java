package cloud.tianai.crypto.cipher.core;

import cloud.tianai.crypto.exception.CryptoCipherException;
import cloud.tianai.crypto.stream.CipherInputStream;
import cloud.tianai.crypto.stream.CipherOutputStream;
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
    byte[] encryptedIV;
    byte[] encryptedCEK;
    byte[] headerData;
    Cipher internalCipher;

    @SneakyThrows
    public AbstractCryptoCipher(Cipher cipher, int model) {
        super(cipher, model);

    }

    @Override
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        return internalCipher.update(input, inputOffset, inputLen);
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
    public byte[] earlyLoadingHeaderData(CipherOutputStream source) {
        return getHeaderData(source.getDelegateStream());
    }

    @Override
    public byte[] start(CipherInputStream source) {
        return getHeaderData(source.getDelegateStream());
    }


    @Override
    public byte[] start(CipherOutputStream source) {
        return getHeaderData(source.getDelegateStream());
    }

    public byte[] getHeaderData(InputStream source) {
        if (headerData == null) {
            if (Cipher.ENCRYPT_MODE == getModel()) {
                // 加密
                headerData = encrypt();
            } else {
                // 解密
                headerData = decrypt(source);
            }
        }
        return headerData;
    }


    public byte[] getHeaderData(OutputStream source) {
        headerData = encrypt();
        return headerData;
    }


    @SneakyThrows
    protected byte[] decrypt(InputStream source) {
        // 解密文件
        DataInputStream dataInputStream = new DataInputStream(source);
        // 版本号
        boolean matchVersion = postProcessBeforeMatchVersion(source);
        int version = -1;
        if (matchVersion) {
            version = dataInputStream.readInt();
            if (getVersion() != version) {
                // 如果不是 v1 版本，那就抛个异常
                throw new CryptoCipherException("不支持的加密版本:" + version);
            }
        }
        byte[] bytes = postProcessAfterMatchVersion(dataInputStream);
        if (bytes != null) {
            return bytes;
        }
        int encryptIvLength = dataInputStream.readInt();
        int encryptCekLength = dataInputStream.readInt();
        this.encryptedIV = new byte[encryptIvLength];
        this.encryptedCEK = new byte[encryptCekLength];

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
        // 初始化解密
        initDecryptAes();

        if (log.isDebugEnabled()) {
            log.debug("init AES Decrypt Cipher \r\n version:{}\r\n IV:{}, \r\n CEK:{},\r\n encryptIV:{}, \r\n encryptCEK:{}",
                    version,
                    Arrays.toString(this.iv),
                    Arrays.toString(this.secretKey.getEncoded()),
                    Arrays.toString(this.encryptedIV),
                    Arrays.toString(this.encryptedCEK));
        }
        return null;
    }

    /**
     * 读取并匹配版本之前，返回true跳过匹配版本
     * @param source source
     * @return boolean
     */
    protected boolean postProcessBeforeMatchVersion(InputStream source) {
        return true;
    }

    /**
     * 读取并匹配版本之后
     * @param source source
     * @return byte[] 不为空则不往下执行，直接返回当前数据，为空则继续往下执行
     */
    protected byte[] postProcessAfterMatchVersion(InputStream source) {
        return null;
    }


    @SneakyThrows
    protected void initDecryptAes() {
        // 解密向量
        this.iv = getCipher().doFinal(this.encryptedIV);
        byte[] cekBytes = getCipher().doFinal(this.encryptedCEK);
        this.secretKey = new SecretKeySpec(cekBytes, getAlgorithm());
        this.internalCipher = createCryptoCipherFromContentMaterial(this.iv, this.secretKey, model);
    }


    @SneakyThrows
    protected void initEncryptAes() {
        this.iv = generateIV();
        this.secretKey = generateCEK();
        this.internalCipher = createCryptoCipherFromContentMaterial(this.iv, this.secretKey, model);
        encryptedIV = cipher.doFinal(this.iv);
        encryptedCEK = cipher.doFinal(this.secretKey.getEncoded());
    }

    /**
     * 加密准备
     *
     * @return byte[]
     */
    @SneakyThrows
    protected byte[] encrypt() {
        initEncryptAes();
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
                    Arrays.toString(this.encryptedIV),
                    Arrays.toString(this.encryptedCEK));
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

    protected SecureRandom getRandom() {
        return new SecureRandom();
    }

    public abstract String getAlgorithm();

    public abstract String getContentCipherAlgorithm();

    public abstract int getKeyLength();

    public abstract int getIvLength();
}
