package cloud.tianai.crypto.cipher.core;

import cloud.tianai.crypto.stream.CipherInputStream;
import cloud.tianai.crypto.stream.CipherOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * @Author: 天爱有情
 * @Date 2020/9/2 15:25
 * @Description 加密的密码接口
 */
public interface CryptoCipher {


    /**
     * {@link javax.crypto.Cipher#ENCRYPT_MODE} 加密
     * {@link javax.crypto.Cipher#DECRYPT_MODE} 解密
     *
     * @return int
     */
    int getModel();

    /**
     * 上传完后最终执行的方法， 适用于在文件尾加一些数据
     *
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    byte[] end() throws IllegalBlockSizeException, BadPaddingException;


    /**
     * 加解密执行的函数
     *
     * @param input       原字节
     * @param inputOffset offset
     * @param inputLen    inputLen
     * @return 加解密返回的内容
     */
    byte[] update(byte[] input, int inputOffset, int inputLen);

    byte[] earlyLoadingHeaderData(CipherInputStream source);

    byte[] earlyLoadingHeaderData(CipherOutputStream source);

    /**
     * 开始读取信息了, 给加密和解密函数预留自定义读取文件字节接口，用作加密/解密前准备
     *
     * @param source 原文件流
     */
    byte[] start(CipherInputStream source);

    byte[] start(CipherOutputStream source);


    /**
     * 重新创建一个新的 CryptoCipher
     *
     * @return CryptoCipher
     */
    CryptoCipher recreate();

    /**
     * 获取版本号
     *
     * @return int
     */
    int getVersion();

}
