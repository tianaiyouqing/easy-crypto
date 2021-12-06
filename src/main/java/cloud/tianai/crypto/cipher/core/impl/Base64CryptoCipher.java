package cloud.tianai.crypto.cipher.core.impl;

import cloud.tianai.crypto.cipher.core.CryptoCipher;
import cloud.tianai.crypto.stream.CipherInputStream;
import cloud.tianai.crypto.stream.CipherOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.util.Base64;

/**
 * @Author: 天爱有情
 * @date 2021/11/27 14:59
 * @Description base64加解密
 */
public class Base64CryptoCipher implements CryptoCipher {

    private int model;
    private int bufferSize;

    public Base64CryptoCipher(int model) {
        this(model, 4096);
    }

    /**
     * 注意： 这里指定的 bufferSize会影响到加密流的buffer， 也就是说这里指定的buff长度和加密流中的长度不一样时，会使用这里的长度,
     * 因为类似于base64这种加密后解密需要加密长度的加密(转码)算法时，必须由算法本身规定长度
     *
     * @param model      model
     * @param bufferSize buff长度
     */
    public Base64CryptoCipher(int model, int bufferSize) {
        this.model = model;
        this.bufferSize = bufferSize;
    }

    @Override
    public int getModel() {
        return model;
    }

    @Override
    public byte[] end() throws IllegalBlockSizeException, BadPaddingException {
        return new byte[0];
    }

    @Override
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        return transcode(input, inputOffset, inputLen);
    }

    @Override
    public byte[] earlyLoadingHeaderData(CipherInputStream source) {
        int length = calcLength();
        if (source.getBuffSize() != length) {
            // 强制改成 bas64指定的长度
            source.setBuffSize(length);
        }
        return new byte[0];
    }

    @Override
    public byte[] start(CipherInputStream source) {
        int length = calcLength();
        if (source.getBuffSize() != length) {
            // 强制改成 bas64指定的长度
            source.setBuffSize(length);
        }
        return new byte[0];
    }

    @Override
    public CryptoCipher recreate() {
        return new Base64CryptoCipher(model);
    }

    @Override
    public int getVersion() {
        return 3;
    }

    @Override
    public byte[] start(CipherOutputStream source) {
        // output暂时不做处理
        return new byte[0];
    }

    @Override
    public byte[] earlyLoadingHeaderData(CipherOutputStream source) {
        // output暂时不做处理
        return new byte[0];
    }


    public byte[] transcode(byte[] source, int offset, int length) {
        byte[] input = new byte[length];
        System.arraycopy(source, offset, input, 0, length);
        if (model == Cipher.ENCRYPT_MODE) {
            return Base64.getEncoder().encode(input);
        }
        return Base64.getDecoder().decode(input);
    }


    public int calcLength() {
        return Cipher.ENCRYPT_MODE == model ? bufferSize : 4 * ((bufferSize + 2) / 3);
    }
}
