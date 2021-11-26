package cloud.tianai.crypto.check;

import java.util.zip.Checksum;

/**
 * @Author: 天爱有情
 * @date 2021/11/26 14:20
 * @Description Checksum 增强
 */
public interface EnhanceChecksum<R> extends Checksum {

    /**
     * 扩展一下，自定义返回数据，不是必须返回long， 比如md5之类的
     *
     * @return R
     */
    R getCheckValue();


    /**
     * 弃用这个方法，建议使用  getCheckValue()
     * @return
     */
    @Override
    @Deprecated
    default long getValue() {
        return 0L;
    }
}
