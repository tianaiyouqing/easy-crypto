package cloud.tianai.crypto.check.impl;

import cloud.tianai.crypto.check.EnhanceChecksum;

import java.util.zip.Checksum;

/**
 * @Author: 天爱有情
 * @date 2021/11/26 14:28
 * @Description Checksum 适配到 EnhanceChecksum
 */
public class ChecksumAdapter implements EnhanceChecksum<Long> {

    private Checksum checksum;

    public ChecksumAdapter(Checksum checksum) {
        this.checksum = checksum;
    }

    @Override
    public long getValue() {
        return checksum.getValue();
    }

    @Override
    public Long getCheckValue() {
        return checksum.getValue();
    }

    @Override
    public void update(int b) {
        checksum.update(b);
    }

    @Override
    public void update(byte[] b, int off, int len) {
        checksum.update(b, off, len);
    }

    @Override
    public void reset() {
        checksum.reset();
    }
}
