package cloud.tianai.crypto.exception;

/**
 * @Author: 天爱有情
 * @date 2021/11/25 9:25
 * @Description 密码相关异常
 */
public class CryptoCipherException extends CryptoException{

    public CryptoCipherException() {
    }

    public CryptoCipherException(String message) {
        super(message);
    }

    public CryptoCipherException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoCipherException(Throwable cause) {
        super(cause);
    }

    public CryptoCipherException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
