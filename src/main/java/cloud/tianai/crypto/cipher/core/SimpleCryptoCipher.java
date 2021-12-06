package cloud.tianai.crypto.cipher.core;

import cloud.tianai.crypto.stream.CipherInputStream;
import cloud.tianai.crypto.stream.CipherOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * @Author: 天爱有情
 * @Date 2020/9/2 15:25
 * @Description 加密的密码
 */
public class SimpleCryptoCipher implements CryptoCipher {

    /**
     * 密码.
     */
    protected Cipher cipher;

    /** model， 标识加密还是解密. */
    protected int model;

    public SimpleCryptoCipher(Cipher cipher, int model) {
        this.cipher = cipher;
        this.model = model;
    }

    public Cipher getCipher() {
        return this.cipher;
    }

    @Override
    public int getModel() {
        return this.model;
    }

    /**
     * 上传完后最终执行的方法， 适用于在文件尾加一些数据
     *
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    @Override
    public byte[] end() throws IllegalBlockSizeException, BadPaddingException {
        return cipher.doFinal();
    }

    /**
     * 加解密执行的函数
     *
     * @param input       原字节
     * @param inputOffset offset
     * @param inputLen    inputLen
     * @return 加解密返回的内容
     */
    @Override
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        return cipher.update(input, inputOffset, inputLen);
    }

    @Override
    public byte[] earlyLoadingHeaderData(CipherInputStream source) {
        return new byte[0];
    }

    /**
     * 开始读取信息了, 给加密和解密函数预留自定义读取文件字节接口，用作加密/解密前准备
     *
     * @param source 原文件流
     */
    @Override
    public byte[] start(CipherInputStream source) {
        return null;
    }

    /**
     * 重新创建一个新的 CryptoCipher
     *
     * @return CryptoCipher
     */
    @Override
    public CryptoCipher recreate() {
        return new SimpleCryptoCipher(this.cipher, this.model);
    }

    @Override
    public int getVersion() {
        return 0;
    }


    /**
     * 开始读取信息了, 给加密和解密函数预留自定义读取文件字节接口，用作加密/解密前准备
     *
     * @param source 原文件流
     */
    @Override
    public byte[] start(CipherOutputStream source) {
        return null;
    }

    @Override
    public byte[] earlyLoadingHeaderData(CipherOutputStream source) {
        return new byte[0];
    }

}
