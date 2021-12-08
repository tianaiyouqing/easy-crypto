package cloud.tianai.crypto;

import cloud.tianai.crypto.check.impl.*;
import cloud.tianai.crypto.cipher.util.CryptoRuntime;
import cloud.tianai.crypto.stream.EnhanceCheckedInputStream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class CheckedTest {
    static {
        CryptoRuntime.enableBouncyCastle();
    }

    /**
     * 获取一个文件的 md5
     */
    @Test
    public void getFileMd5() throws IOException {
        // 源文件
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\预览20M.pdf");
        Md5Checksum md5Checksum = new Md5Checksum();
        EnhanceCheckedInputStream checkedInputStream = new EnhanceCheckedInputStream(source, md5Checksum);
        readAll(checkedInputStream);
        byte[] md5 = md5Checksum.getCheckValue();
        System.out.println("md5:" + Hex.toHexString(md5));
    }

    /**
     * 获取一个文件的 crc64
     */
    @Test
    public void getFileCrc64() throws IOException {
        // 源文件
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\预览20M.pdf");
        CRC64Checksum crc64Checksum = new CRC64Checksum();
        EnhanceCheckedInputStream checkedInputStream = new EnhanceCheckedInputStream(source, crc64Checksum);
        readAll(checkedInputStream);
        Long crc64 = crc64Checksum.getCheckValue();
        System.out.println("crc64:" + crc64);
    }


    /**
     * 同时获取一个文件的  md5、crc64、sha256
     */
    @Test
    public void getFileChecksum() throws IOException {
        Md5Checksum md5Checksum = new Md5Checksum();
        CRC64Checksum crc64Checksum = new CRC64Checksum();
        Sha256Checksum sha256Checksum = new Sha256Checksum();
        MultiPartChecksum multiPartChecksum = new MultiPartChecksum(md5Checksum, crc64Checksum, sha256Checksum);

        long start = System.currentTimeMillis();
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\source.zip");
        EnhanceCheckedInputStream checkedInputStream = new EnhanceCheckedInputStream(source, multiPartChecksum);
        readAll(checkedInputStream);
        long end = System.currentTimeMillis();
        System.out.println("文件大小:1.91 GB");
        System.out.println("md5:" + Hex.toHexString(md5Checksum.getCheckValue()));
        System.out.println("crc64:" + crc64Checksum.getCheckValue());
        System.out.println("sha256:" + Hex.toHexString(sha256Checksum.getCheckValue()));
        System.out.println("耗时:" + (end - start) + "ms");

    }


    /**
     * 获取一个文件的 md5
     */
    @Test
    public void getFileSM3() throws IOException {
        // 源文件
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\预览20M.pdf");
        DigestChecksum checksum = new DigestChecksum("SM3");
        EnhanceCheckedInputStream checkedInputStream = new EnhanceCheckedInputStream(source, checksum);
        readAll(checkedInputStream);
        byte[] md5 = checksum.getCheckValue();
        System.out.println("sm3:" + Hex.toHexString(md5));
    }

    public void readAll(InputStream input) throws IOException {
        byte[] buffer = new byte[4096];
        while (-1 != input.read(buffer)) {

        }
    }
}
