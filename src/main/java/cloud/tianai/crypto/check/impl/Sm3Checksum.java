package cloud.tianai.crypto.check.impl;


import cloud.tianai.crypto.cipher.util.CryptoRuntime;

/**
 * @Author: 天爱有情
 * @date 2021/12/8 14:36
 * @Description SM3 CheckSum
 */
public class Sm3Checksum extends DigestChecksum {

    static {
        CryptoRuntime.enableBouncyCastle();
    }


    public Sm3Checksum() {
        super("SM3");
    }
}
