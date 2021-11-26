package cloud.tianai.crypto.stream;

import cloud.tianai.crypto.check.EnhanceChecksum;
import cloud.tianai.crypto.check.impl.ChecksumAdapter;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Checksum;

/**
 * @Author: 天爱有情
 * @date 2021/11/26 14:32
 * @Description 重写java的 CheckedInputStream
 */
public class EnhanceCheckedInputStream extends FilterInputStream {
    private EnhanceChecksum cksum;

    /**
     * Creates an input stream using the specified Checksum.
     *
     * @param in    the input stream
     * @param cksum the Checksum
     */
    public EnhanceCheckedInputStream(InputStream in, Checksum cksum) {
        super(in);
        if (cksum instanceof EnhanceChecksum) {
            this.cksum = (EnhanceChecksum) cksum;
        } else {
            this.cksum = new ChecksumAdapter(cksum);
        }
    }

    /**
     * Reads a byte. Will block if no input is available.
     *
     * @return the byte read, or -1 if the end of the stream is reached.
     * @throws IOException if an I/O error has occurred
     */
    @Override
    public int read() throws IOException {
        int b = in.read();
        if (b != -1) {
            cksum.update(b);
        }
        return b;
    }

    /**
     * Reads into an array of bytes. If <code>len</code> is not zero, the method
     * blocks until some input is available; otherwise, no
     * bytes are read and <code>0</code> is returned.
     *
     * @param buf the buffer into which the data is read
     * @param off the start offset in the destination array <code>b</code>
     * @param len the maximum number of bytes read
     * @return the actual number of bytes read, or -1 if the end
     * of the stream is reached.
     * @throws NullPointerException      If <code>buf</code> is <code>null</code>.
     * @throws IndexOutOfBoundsException If <code>off</code> is negative,
     *                                   <code>len</code> is negative, or <code>len</code> is greater than
     *                                   <code>buf.length - off</code>
     * @throws IOException               if an I/O error has occurred
     */
    @Override
    public int read(byte[] buf, int off, int len) throws IOException {
        len = in.read(buf, off, len);
        if (len != -1) {
            cksum.update(buf, off, len);
        }
        return len;
    }

    /**
     * Skips specified number of bytes of input.
     *
     * @param n the number of bytes to skip
     * @return the actual number of bytes skipped
     * @throws IOException if an I/O error has occurred
     */
    @Override
    public long skip(long n) throws IOException {
        byte[] buf = new byte[512];
        long total = 0;
        while (total < n) {
            long len = n - total;
            len = read(buf, 0, len < buf.length ? (int) len : buf.length);
            if (len == -1) {
                return total;
            }
            total += len;
        }
        return total;
    }

    /**
     * Returns the Checksum for this input stream.
     *
     * @return the Checksum value
     */
    public <R> EnhanceChecksum<R> getChecksum() {
        return cksum;
    }

}
