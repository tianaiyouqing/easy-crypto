package cloud.tianai.crypto.check.impl;


import cloud.tianai.crypto.check.EnhanceChecksum;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @Author: 天爱有情
 * @date 2021/11/26 14:25
 * @Description MD5 CheckSum
 */
public class Md5Checksum implements EnhanceChecksum<byte[]> {

    MessageDigest messageDigest;

    public Md5Checksum() {
        try {
            messageDigest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {

        }
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
    public byte[] getCheckValue() {
        return messageDigest.digest();
    }

    @Override
    public long getValue() {
        return 0;
    }

    @Override
    public void reset() {
        try {
            messageDigest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {

        }
    }
}
