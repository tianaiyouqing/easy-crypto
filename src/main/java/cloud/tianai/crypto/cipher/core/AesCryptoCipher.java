package cloud.tianai.crypto.cipher.core;

import cloud.tianai.crypto.exception.CryptoCipherException;
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
 * @Description 底层加密算法为 AES ， 外层算法为自定义的算法框架
 * <p>
 * 算法流的格式
 * +---------+-----------+----------+---------+--------+------+
 * | version | cekLength | ivLength | cekData | ivData | data |
 * +---------+-----------+----------+---------+--------+------+
 */
@Slf4j
public class AesCryptoCipher extends CryptoCipher {

    public static final String CONTENT_CIPHER_ALGORITHM = "AES/CTR/NoPadding";
    public static final String KEY_GENERATOR_ALGORITHM = "AES";
    public static final int KEY_LENGTH_IN_BITS = 256;
    public static final int CIPHER_IV_LENGTH = 16;
    public static final int VERSION_V1 = 1;

    private static final SecureRandom RANDOM = new SecureRandom();

    private byte[] iv;
    private SecretKey secretKey;
    private byte[] encryptedIV;
    private byte[] encryptedCEK;
    private byte[] headerData;
    private Cipher aesCipher;

    @SneakyThrows
    public AesCryptoCipher(Cipher cipher, int model) {
        super(cipher, model);

    }

    @Override
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        return aesCipher.update(input, inputOffset, inputLen);
    }

    @Override
    public byte[] end() throws IllegalBlockSizeException, BadPaddingException {
        if (aesCipher == null) {
            return new byte[0];
        }
        return aesCipher.doFinal();
    }

    @Override
    public byte[] earlyLoadingHeaderData(InputStream source) {
        return getHeaderData(source);
    }

    @Override
    public byte[] earlyLoadingHeaderData(OutputStream source) {
        return getHeaderData(source);
    }

    @Override
    public byte[] start(InputStream source) {
        return getHeaderData(source);
    }


    @Override
    public byte[] start(OutputStream source) {
        return getHeaderData(source);
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
    private byte[] decrypt(InputStream source) {
        // 解密文件
        DataInputStream dataInputStream = new DataInputStream(source);
        // 版本号
        int version = dataInputStream.readInt();
        if (VERSION_V1 != version) {
            // 如果不是 v1 版本，那就抛个异常
            throw new CryptoCipherException("不支持的加密版本:" + version);
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

    @SneakyThrows
    private void initDecryptAes() {
        // 解密向量
        this.iv = getCipher().doFinal(this.encryptedIV);
        byte[] cekBytes = getCipher().doFinal(this.encryptedCEK);
        this.secretKey = new SecretKeySpec(cekBytes, KEY_GENERATOR_ALGORITHM);
        this.aesCipher = createCryptoCipherFromContentMaterial(this.iv, this.secretKey, model);
    }


    @SneakyThrows
    private void initEncryptAes() {
        this.iv = generateIV();
        this.secretKey = generateCEK();
        this.aesCipher = createCryptoCipherFromContentMaterial(this.iv, this.secretKey, model);
        encryptedIV = cipher.doFinal(this.iv);
        encryptedCEK = cipher.doFinal(this.secretKey.getEncoded());
    }

    /**
     * 加密准备
     *
     * @return byte[]
     */
    @SneakyThrows
    private byte[] encrypt() {
        initEncryptAes();
        int encryptCekLength = encryptedCEK.length;
        int encryptIvLength = encryptedIV.length;

        ByteArrayOutputStream output = new ByteArrayOutputStream(12 + encryptCekLength + encryptIvLength);
        DataOutputStream dataOutputStream = new DataOutputStream(output);

        // 版本号
        dataOutputStream.writeInt(VERSION_V1);
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
                    VERSION_V1,
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
    public static Cipher createCryptoCipherFromContentMaterial(byte[] iv, SecretKey cek, int cipherMode) {
        Cipher cipher;
        cipher = Cipher.getInstance(CONTENT_CIPHER_ALGORITHM);
        cipher.init(cipherMode, cek, new IvParameterSpec(iv));
        return cipher;
    }

    private static SecretKey generateCEK() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(KEY_GENERATOR_ALGORITHM);
            generator.init(KEY_LENGTH_IN_BITS, RANDOM);
            SecretKey secretKey;
            for (int retry = 0; retry < 9; retry++) {
                secretKey = generator.generateKey();
                if (secretKey.getEncoded()[0] != 0) {
                    return secretKey;
                }
            }
            throw new CryptoCipherException("Failed to generate secret key");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoCipherException("No such algorithm:" + KEY_GENERATOR_ALGORITHM + ", " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("AlibabaLowerCamelCaseVariableNaming")
    private static byte[] generateIV() {
        final byte[] iv = new byte[CIPHER_IV_LENGTH];
        RANDOM.nextBytes(iv);
        for (int i = 8; i < 12; i++) {
            iv[i] = 0;
        }
        return iv;
    }


    @Override
    public CryptoCipher recreate() {
        return new AesCryptoCipher(getCipher(), getModel());
    }
}
