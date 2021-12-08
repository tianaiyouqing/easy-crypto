package cloud.tianai.crypto.check.impl;

import cloud.tianai.crypto.check.EnhanceChecksum;
import lombok.SneakyThrows;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @Author: 天爱有情
 * @date 2021/12/8 14:28
 * @Description MessageDigest 通用算法校验
 */
public class DigestChecksum implements EnhanceChecksum<byte[]> {

    protected MessageDigest messageDigest;
    protected String algorithm;

    public DigestChecksum(String algorithm) {
        this.algorithm = algorithm;
        createMessageDigest();

    }

    @SneakyThrows(NoSuchAlgorithmException.class)
    private void createMessageDigest() {
        messageDigest = MessageDigest.getInstance(algorithm);
    }

    @Override
    public byte[] getCheckValue() {
        return messageDigest.digest();
    }

    @Override
    public void update(int b) {
        messageDigest.update(Integer.valueOf(b).byteValue());
    }

    @Override
    public void update(byte[] b, int off, int len) {
        messageDigest.update(b, off, len);
    }

    @Override
    public void reset() {
        createMessageDigest();
    }
}
