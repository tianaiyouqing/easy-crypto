package cloud.tianai.crypto.exception;

/**
 * @Author: 天爱有情
 * @date 2021/11/25 9:20
 * @Description
 */
public class CryptoException extends RuntimeException{

    public CryptoException() {
    }

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoException(Throwable cause) {
        super(cause);
    }

    public CryptoException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
