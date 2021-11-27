

package cloud.tianai.crypto.stream;


import cloud.tianai.crypto.exception.CryptoException;

import java.io.*;

/**
 * @Author: 天爱有情
 * @date 2021/11/25 9:49
 * @Description 增强的 FilterOutputStream
 */
public class SdkFilterOutputStream extends FilterOutputStream {
    private volatile boolean aborted = false;

    public SdkFilterOutputStream(OutputStream out) {
        super(out);
    }

    /**
     * @return The wrapped stream.
     */
    public OutputStream getDelegateStream() {
        return out;
    }

    /**
     * Aborts the inputstream operation if thread is interrupted.
     * interrupted status of the thread is cleared by this method.
     *
     * @throws CryptoException with CryptoException INPUTSTREAM_READING_ABORTED if thread aborted.
     */
    protected final void abortIfNeeded() {
        if (shouldAbort()) {
            abort();
            throw new CryptoException("Thread aborted, inputStream aborted...");
        }
    }

    public void abort() {
        if (out instanceof SdkFilterOutputStream) {
            ((SdkFilterOutputStream) out).abort();
        }
        aborted = true;
    }

    public boolean isAborted() {
        return aborted;
    }


    @Override
    public void write(int b) throws IOException {
        abortIfNeeded();
        out.write(b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        abortIfNeeded();
        out.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        abortIfNeeded();
        out.write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
        abortIfNeeded();
        out.flush();
    }


    @Override
    public void close() throws IOException {
        out.close();
        abortIfNeeded();
    }


    public static boolean shouldAbort() {
        return Thread.interrupted();
    }
}
