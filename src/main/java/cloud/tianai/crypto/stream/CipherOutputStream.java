package cloud.tianai.crypto.stream;


import cloud.tianai.crypto.cipher.core.CryptoCipher;
import cloud.tianai.crypto.exception.CryptoException;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @Author: 天爱有情
 * @date 2021/11/25 10:09
 * @Description 带有密码的输出流
 */
@Slf4j
public class CipherOutputStream extends SdkFilterOutputStream {
    private final AtomicBoolean firstRead = new AtomicBoolean(false);
    private CryptoCipher cryptoCipher;

    public CipherOutputStream(OutputStream os, CryptoCipher c) {
        super(os);
//        if (Cipher.ENCRYPT_MODE != c.getModel()) {
//            // 暂时不支持加密操作，只支持加密操作
//            throw new CryptoException("CipherOutputStream暂时只支持加密操作，不支持解密, 建议使用 CipherInputStream 做解密操作");
//        }
        this.cryptoCipher = c;
    }


    @Override
    public void write(int b) throws IOException {
        byte[] bytes = new byte[]{(byte) b};
        this.write(bytes, 0, 1);
    }

    @Override
    public void write(byte[] b) throws IOException {
        this.write(b, 0, b.length);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (firstRead.compareAndSet(false, true)) {
            // 第一次写
            byte[] start = cryptoCipher.start(b, off, len);
            if(start != null && start.length > 0) {
                out.write(start);
            }
        }
        byte[] update = cryptoCipher.update(b, off, len);
        out.write(update);
    }


    @Override
    public void close() throws IOException {
        try {
            byte[] end = cryptoCipher.end();
            if (end != null && end.length > 0) {
                out.write(end);
            }
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            log.warn("cryptoCipher.end() warn", ex);
        }
        out.close();
    }


}
