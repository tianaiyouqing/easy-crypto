package cloud.tianai.crypto.cipher.core;

import lombok.Getter;

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
@Getter
public class CryptoCipher {

    /**
     * 密码.
     */
    protected Cipher cipher;

    /** model， 标识加密还是解密. */
    protected int model;

    public CryptoCipher(Cipher cipher, int model) {
        this.cipher = cipher;
        this.model = model;
    }

    /**
     * 上传完后最终执行的方法， 适用于在文件尾加一些数据
     *
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
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
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        return cipher.update(input, inputOffset, inputLen);
    }


    public byte[] earlyLoadingHeaderData(InputStream source) {
        return new byte[0];
    }

    /**
     * 开始读取信息了, 给加密和解密函数预留自定义读取文件字节接口，用作加密/解密前准备
     *
     * @param source 原文件流
     */
    public byte[] start(InputStream source) {
        return null;
    }

    /**
     * 重新创建一个新的 CryptoCipher
     *
     * @return CryptoCipher
     */
    public CryptoCipher recreate() {
        return new CryptoCipher(this.cipher, this.model);
    }


    /**
     * 开始读取信息了, 给加密和解密函数预留自定义读取文件字节接口，用作加密/解密前准备
     *
     * @param source 原文件流
     */
    public byte[] start(OutputStream source) {
        return null;
    }

    public byte[] earlyLoadingHeaderData(OutputStream source) {
        return new byte[0];
    }

}
