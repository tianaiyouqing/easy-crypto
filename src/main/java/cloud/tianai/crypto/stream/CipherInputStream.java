package cloud.tianai.crypto.stream;


import cloud.tianai.crypto.cipher.core.CryptoCipher;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @Author: 天爱有情
 * @date 2021/11/25 10:11
 * @Description 带有密码的输入流, 支持加解密操作
 */
@Slf4j
public class CipherInputStream extends SdkFilterInputStream {
    private static final int MAX_RETRY = 1000;
    private static final int DEFAULT_IN_BUFFER_SIZE = 4096;
    public static final int POSITIVE_MULTIPLE = 64;
    private final AtomicBoolean firstRead = new AtomicBoolean(false);
    private CryptoCipher cryptoCipher;

    private boolean hasBeenAccessed;
    private byte[] bufIn;
    private int bufferSize;
    private boolean eof;
    private byte[] bufOut;
    private int currPos;
    private int maxPos;

    public CipherInputStream(InputStream is, CryptoCipher cryptoCipher) {
        this(is, cryptoCipher, DEFAULT_IN_BUFFER_SIZE);
    }

    public CipherInputStream(InputStream is, CryptoCipher c, int buffSize) {
        super(is);
        this.cryptoCipher = c;
//        if (buffSize <= 0 || (buffSize % POSITIVE_MULTIPLE) != 0) {
//            throw new IllegalArgumentException(
//                    "buffSize (" + buffSize + ") must be a positive multiple of " + POSITIVE_MULTIPLE);
//        }
        this.bufferSize = buffSize;
    }

    public int getBuffSize() {
        return this.bufferSize;
    }

    public void setBuffSize(int bufferSize) {
        this.bufferSize = bufferSize;
    }

    public byte[] getBufIn() {
        if (this.bufIn == null) {
            this.bufIn = new byte[this.bufferSize];
        }
        return this.bufIn;
    }

    public void setBufIn(byte[] bufIn) {
        this.bufIn = bufIn;
    }

    public int earlyEncryptGetHeaderSize() {
        byte[] headerData = cryptoCipher.earlyLoadingHeaderData(this);
        return headerData != null? headerData.length : 0;
    }

    @Override
    public int read() throws IOException {
        hasBeenAccessed = true;
        if (readChunkIfNecessary() == -1) {
            return -1;
        }
        return ((int) bufOut[currPos++] & 0xFF);
    }

    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte[] buf, int off, int targetLen) throws IOException {
        hasBeenAccessed = true;
        if (readChunkIfNecessary() == -1) {
            return -1;
        }
        if (targetLen <= 0) {
            return 0;
        }
        int len = maxPos - currPos;
        if (targetLen < len) {
            len = targetLen;
        }

        System.arraycopy(bufOut, currPos, buf, off, len);
        currPos += len;
        return len;
    }


    protected int readChunkIfNecessary() throws IOException {
        int len = 0;
        if (currPos >= maxPos) {
            if (eof) {
                return -1;
            }
            int count = 0;
            do {
                if (count > MAX_RETRY) {
                    throw new IOException("exceeded maximum number of attempts to read next chunk of data");
                }
                len = nextChunk();
                count++;
            } while (len == 0);

        }
        return len;
    }

    /**
     * Note: This implementation will only skip up to the end of the buffered data,
     * potentially skipping 0 bytes.
     */
    @Override
    public long skip(long n) {
        abortIfNeeded();
        hasBeenAccessed = true;
        int available = maxPos - currPos;
        if (n > available) {
            n = available;
        }
        if (n < 0) {
            return 0;
        }
        currPos += n;
        return n;
    }

    @Override
    public int available() {
        abortIfNeeded();
        return maxPos - currPos;
    }

    @Override
    public void close() throws IOException {
        in.close();
        try {
            cryptoCipher.end();
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            log.warn("cryptoCipher.end() warn", ex);
        }
        currPos = maxPos = 0;
        abortIfNeeded();
    }

    @Override
    public boolean markSupported() {
        abortIfNeeded();
        return in.markSupported();
    }

    @Override
    public void mark(int readLimit) {
        if (hasBeenAccessed) {
            throw new UnsupportedOperationException(
                    "Marking is only supported before your first call to " + "read or skip.");
        }
        in.mark(readLimit);
    }

    @Override
    public void reset() throws IOException {
        abortIfNeeded();
        in.reset();
        resetInternal();
    }

    final void resetInternal() {
        currPos = maxPos = 0;
        eof = false;
        hasBeenAccessed = false;
        firstRead.set(false);
        cryptoCipher = cryptoCipher.recreate();
    }

    /**
     * Reads and process the next chunk of data into memory.
     *
     * @return the length of the data chunk read and processed, or -1 if end of
     * stream.
     * @throws IOException       if there is an IO exception from the underlying input stream
     * @throws SecurityException if there is authentication failure
     */
    protected int nextChunk() throws IOException {
        abortIfNeeded();
        if (eof) {
            return -1;
        }
        bufOut = null;
        if (firstRead.compareAndSet(false, true)) {
            // 第一次读
            // 做读处理
            // 如果返回了数据，则不往下执行
            bufOut = cryptoCipher.start(this);
            if (bufOut != null && bufOut.length > 0) {
                currPos = 0;
                return maxPos = bufOut.length;
            }
        }
        byte[] bufIn = getBufIn();
        int len = in.read(bufIn);
        if (len == -1) {
            eof = true;
            try {
                bufOut = cryptoCipher.end();
                if (bufOut == null) {
                    return -1;
                }
                currPos = 0;
                return maxPos = bufOut.length;
            } catch (IllegalBlockSizeException ignored) {
            } catch (BadPaddingException e) {
                throw new SecurityException(e);
            }
            return -1;
        }

        // 解密/加密
        bufOut = cryptoCipher.update(bufIn, 0, len);
        currPos = 0;
        return maxPos = (bufOut == null ? 0 : bufOut.length);
    }
}
