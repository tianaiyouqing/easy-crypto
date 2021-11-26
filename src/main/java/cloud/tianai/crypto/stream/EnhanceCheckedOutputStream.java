package cloud.tianai.crypto.stream;

import cloud.tianai.crypto.check.EnhanceChecksum;
import cloud.tianai.crypto.check.impl.ChecksumAdapter;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.Checksum;

/**
 * @Author: 天爱有情
 * @date 2021/11/26 14:37
 * @Description 重写java的 CheckedOutputStream
 */
public class EnhanceCheckedOutputStream extends FilterOutputStream {
    private EnhanceChecksum cksum;


    /**
     * Creates an output stream with the specified Checksum.
     *
     * @param out   the output stream
     * @param cksum the checksum
     */
    public EnhanceCheckedOutputStream(OutputStream out, Checksum cksum) {
        super(out);
        if (cksum instanceof EnhanceChecksum) {
            this.cksum = (EnhanceChecksum) cksum;
        } else {
            this.cksum = new ChecksumAdapter(cksum);
        }
    }

    /**
     * Writes a byte. Will block until the byte is actually written.
     *
     * @param b the byte to be written
     * @throws IOException if an I/O error has occurred
     */
    public void write(int b) throws IOException {
        out.write(b);
        cksum.update(b);
    }

    /**
     * Writes an array of bytes. Will block until the bytes are
     * actually written.
     *
     * @param b   the data to be written
     * @param off the start offset of the data
     * @param len the number of bytes to be written
     * @throws IOException if an I/O error has occurred
     */
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len);
        cksum.update(b, off, len);
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
