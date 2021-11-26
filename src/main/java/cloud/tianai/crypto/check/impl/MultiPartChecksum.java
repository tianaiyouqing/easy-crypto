package cloud.tianai.crypto.check.impl;

import cloud.tianai.crypto.check.EnhanceChecksum;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * @Author: 天爱有情
 * @date 2021/11/26 14:51
 * @Description 可以承载多个校验一起校验
 */
public class MultiPartChecksum implements EnhanceChecksum<List<EnhanceChecksum<?>>> {

    private List<EnhanceChecksum<?>> checksumList;


    public MultiPartChecksum(EnhanceChecksum<?>... checksumArr) {
        this.checksumList = new LinkedList<>(Arrays.asList(checksumArr));
    }

    @Override
    public List<EnhanceChecksum<?>> getCheckValue() {
        return checksumList;
    }

    @Override
    public void update(int b) {
        for (EnhanceChecksum<?> checksum : checksumList) {
            checksum.update(b);
        }
    }

    @Override
    public void update(byte[] b, int off, int len) {
        for (EnhanceChecksum<?> checksum : checksumList) {
            checksum.update(b, off, len);
        }
    }

    @Override
    public void reset() {
        for (EnhanceChecksum<?> checksum : checksumList) {
            checksum.reset();
        }
    }
}
