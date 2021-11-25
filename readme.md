# 这是一个高性能的加解密文件(或其它需要加密的)的工具

- 特点一: 使用流式加密/解密， 性能更好，内存损耗更少(几乎不消耗额外内存)；更加方便，更易读
- 特点二: 加密底层均为性能强大的AES加密，外层使用自定义加密算法加密，性能显著提升
- 特点三: 代码结构简单，原理易懂，更加方便扩展， 可使用任意一种加密算法进行文件或其它需要加密的

# 示例代码
- 这里示例使用 3des和RSA和自定义加密算法(sm4) 进行加解密文件操作，各位可以使用自己的加密算法进行加解密
```java
public class CryptoTest {


    /**
     * 使用 CipherInputStream 加密 源文件, 使用3des加密
     */
    @Test
    public void testEncryptByInputStreamAndDes() throws IOException {
        // 源文件
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\预览20M.pdf");
        // 包装成加密流
        CipherInputStream cipherInputStream = new CipherInputStream(source, CryptoCipherBuilder.buildDes3Crypt("123456781234567812345678", true));
        // 输出
        FileOutputStream outputStream = new FileOutputStream("C:\\Users\\Thinkpad\\Desktop\\加密-预览20M.pdf");
        write(cipherInputStream,outputStream);
        outputStream.close();
        cipherInputStream.close();
    }


    /**
     * 使用 CipherInputStream 解密加密的文件, 使用3des解密
     */
    @Test
    public void testDecryptByInputStreamAndDes() throws IOException {
        // 源文件
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\加密-预览20M.pdf");
        // 包装成解密流
        CryptoCipher cryptoCipher = CryptoCipherBuilder.buildDes3Crypt("123456781234567812345678", false);
        CipherInputStream cipherInputStream = new CipherInputStream(source, cryptoCipher);
        // 输出
        FileOutputStream outputStream = new FileOutputStream("C:\\Users\\Thinkpad\\Desktop\\解密-预览20M.pdf");
        write(cipherInputStream,outputStream);
        outputStream.close();
        cipherInputStream.close();
    }



    /**
     * 使用 CipherOutputStream 加密 源文件, 使用3des加密
     */
    @Test
    public void testEncryptByOutputStreamAndDes() throws IOException {
        // 源文件
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\预览20M.pdf");
        // 输出
        FileOutputStream outputStream = new FileOutputStream("C:\\Users\\Thinkpad\\Desktop\\加密-预览20M.pdf");
        // 包装输出流为加密流
        CryptoCipher cryptoCipher = CryptoCipherBuilder.buildDes3Crypt("123456781234567812345678", true);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cryptoCipher);

        write(source,cipherOutputStream);
        outputStream.close();
        cipherOutputStream.close();
    }

    // 使用rsa加解密



    @Test
    public void genRsaKey() {

        String[] keys = RsaUtils.genKeyPair(1024);
        String privateKey = keys[0];
        String publicKey = keys[1];

        // MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAI+3kvvYUfKCIf0vGn7Pbq0ihct+PjtKqVBRg0364ewMZ+y/f2wGDfQflVWclSPF4weIjSPxQKhN64x0VsAybnOUbO1r+UJqpCVXwZdM79wqPXXsLR7OZSG61jjKX1BOEugIn9NPgKklPfmHWwXiBsf2rmsakom9OKeLgZ/jUIQFAgMBAAECgYEAhrDoe0mge6SEkFHOBh0IQBFDzZRyZIUzq4fJhJLlm6GA4LwUgrwl5a6X+ZV3nQBAJvZOOOpIy7PDV25NQ3HAWwA7mEOGYMhi18POWrsQ8+e//Htw6lmbWt1sTl4sodIIaWJNC/9elT0GccAdeEqdRtA5RrZYfajsvi9tIDVQ4r0CQQDJn3jnMhpBXfO2vEWf3V0JMTz9Cn2IrAIn4q8JcRuw5eET1VqBWsIBeA4+VMif91O8lsnVPyhvSTCXhkGEaIMjAkEAtnok3DXtZwHhZKStuC1QN0A6q53tY7muDFV/mTbLbs5xKCvyVkIxQ6jIJrZ86SSb2G2rWbocoafL1B7qG6GCtwJAFrkMTTIOV3OZNez+A8hU5eZQs0vtXevUyl330B6ZOlSOC0guTQnHd5bqNAgmHDEplMWBtbDKg9BB07HjzGJi9QJAPHs7oGmXaF7tMAiNM9CBF+8IAz3zIuy2TYxBIK1SvEVcqC34wrJp1b0pqfsuZ7Akn5WqB7FyL/qHyqT8f3AG/QJAGezbTUI2TBw48PXDkcxVZR4b1iDNgzr6nWkEvbqUvu1SKAJFzs0tKHrBrHDFaWu7UxAmfZ4nodtk6J0Gj4qHKQ==
        System.out.println(privateKey);
        // MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPt5L72FHygiH9Lxp+z26tIoXLfj47SqlQUYNN+uHsDGfsv39sBg30H5VVnJUjxeMHiI0j8UCoTeuMdFbAMm5zlGzta/lCaqQlV8GXTO/cKj117C0ezmUhutY4yl9QThLoCJ/TT4CpJT35h1sF4gbH9q5rGpKJvTini4Gf41CEBQIDAQAB
        System.out.println(publicKey);

    }


    /**
     * 使用 CipherInputStream 加密 源文件, 使用RSA公钥加密
     */
    @Test
    public void testEncryptByInputStreamAndRsa() throws IOException {
        // 源文件
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\预览20M.pdf");
        // 包装成加密流, 使用公钥加密
        RSAPublicKey publicKey = RsaUtils.getPublicKeyFromPemX509("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPt5L72FHygiH9Lxp+z26tIoXLfj47SqlQUYNN+uHsDGfsv39sBg30H5VVnJUjxeMHiI0j8UCoTeuMdFbAMm5zlGzta/lCaqQlV8GXTO/cKj117C0ezmUhutY4yl9QThLoCJ/TT4CpJT35h1sF4gbH9q5rGpKJvTini4Gf41CEBQIDAQAB");
        CryptoCipher cryptoCipher = CryptoCipherBuilder.buildRsaCrypt(publicKey, true);
        CipherInputStream cipherInputStream = new CipherInputStream(source, cryptoCipher);
        // 输出
        FileOutputStream outputStream = new FileOutputStream("C:\\Users\\Thinkpad\\Desktop\\加密-预览20M.pdf");
        write(cipherInputStream,outputStream);
        outputStream.close();
        cipherInputStream.close();
    }


    /**
     * 使用 CipherInputStream 解密加密的文件, 使用rsa私钥解密
     */
    @Test
    public void testDecryptByInputStreamAndRsa() throws IOException {
        // 源文件
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\加密-预览20M.pdf");
        // 包装成解密流, 使用私钥解密
        RSAPrivateKey privateKey = RsaUtils.getPrivateKeyFromPemPKCS8("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAI+3kvvYUfKCIf0vGn7Pbq0ihct+PjtKqVBRg0364ewMZ+y/f2wGDfQflVWclSPF4weIjSPxQKhN64x0VsAybnOUbO1r+UJqpCVXwZdM79wqPXXsLR7OZSG61jjKX1BOEugIn9NPgKklPfmHWwXiBsf2rmsakom9OKeLgZ/jUIQFAgMBAAECgYEAhrDoe0mge6SEkFHOBh0IQBFDzZRyZIUzq4fJhJLlm6GA4LwUgrwl5a6X+ZV3nQBAJvZOOOpIy7PDV25NQ3HAWwA7mEOGYMhi18POWrsQ8+e//Htw6lmbWt1sTl4sodIIaWJNC/9elT0GccAdeEqdRtA5RrZYfajsvi9tIDVQ4r0CQQDJn3jnMhpBXfO2vEWf3V0JMTz9Cn2IrAIn4q8JcRuw5eET1VqBWsIBeA4+VMif91O8lsnVPyhvSTCXhkGEaIMjAkEAtnok3DXtZwHhZKStuC1QN0A6q53tY7muDFV/mTbLbs5xKCvyVkIxQ6jIJrZ86SSb2G2rWbocoafL1B7qG6GCtwJAFrkMTTIOV3OZNez+A8hU5eZQs0vtXevUyl330B6ZOlSOC0guTQnHd5bqNAgmHDEplMWBtbDKg9BB07HjzGJi9QJAPHs7oGmXaF7tMAiNM9CBF+8IAz3zIuy2TYxBIK1SvEVcqC34wrJp1b0pqfsuZ7Akn5WqB7FyL/qHyqT8f3AG/QJAGezbTUI2TBw48PXDkcxVZR4b1iDNgzr6nWkEvbqUvu1SKAJFzs0tKHrBrHDFaWu7UxAmfZ4nodtk6J0Gj4qHKQ==");
        CryptoCipher cryptoCipher = CryptoCipherBuilder.buildRsaCrypt(privateKey, false);
        CipherInputStream cipherInputStream = new CipherInputStream(source, cryptoCipher);
        // 输出
        FileOutputStream outputStream = new FileOutputStream("C:\\Users\\Thinkpad\\Desktop\\解密-预览20M.pdf");
        write(cipherInputStream,outputStream);
        outputStream.close();
        cipherInputStream.close();
    }



    /**
     * 使用 CipherOutputStream 加密 源文件, 使用RSA公钥加密
     */
    @Test
    public void testEncryptByOutputStreamAndRsa() throws IOException {
        // 源文件
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\预览20M.pdf");
        // 输出
        FileOutputStream outputStream = new FileOutputStream("C:\\Users\\Thinkpad\\Desktop\\加密-预览20M.pdf");
        // 包装输出流为加密流,  使用公钥加密
        RSAPublicKey publicKey = RsaUtils.getPublicKeyFromPemX509("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPt5L72FHygiH9Lxp+z26tIoXLfj47SqlQUYNN+uHsDGfsv39sBg30H5VVnJUjxeMHiI0j8UCoTeuMdFbAMm5zlGzta/lCaqQlV8GXTO/cKj117C0ezmUhutY4yl9QThLoCJ/TT4CpJT35h1sF4gbH9q5rGpKJvTini4Gf41CEBQIDAQAB");
        CryptoCipher cryptoCipher = CryptoCipherBuilder.buildRsaCrypt(publicKey, true);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cryptoCipher);

        write(source,cipherOutputStream);
        outputStream.close();
        cipherOutputStream.close();
    }


    /**
     * 使用 CipherInputStream 加密 源文件, 使用自定义算法加密
     */
    @Test
    public void testEncryptByInputStreamAndCustom() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        // 源文件
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\预览20M.pdf");
        // 创建自定义加密算法
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
        byte[] key = Base64.getDecoder().decode("aW6sIKDsH4U9QIXjIshTHw==");
        Key sm4Key = new SecretKeySpec(key, "SM4");
        cipher.init(Cipher.ENCRYPT_MODE, sm4Key);
        AesCryptoCipher aesCryptoCipher = new AesCryptoCipher(cipher, Cipher.ENCRYPT_MODE);

        // 包装成加密流, 使用SM4加密
        CipherInputStream cipherInputStream = new CipherInputStream(source, aesCryptoCipher);
        // 输出
        FileOutputStream outputStream = new FileOutputStream("C:\\Users\\Thinkpad\\Desktop\\加密-预览20M.pdf");
        write(cipherInputStream, outputStream);
        outputStream.close();
        cipherInputStream.close();
    }


    /**
     * 使用 CipherInputStream 解密加密的文件, 使用自定义算法解密
     *
     */
    @Test
    public void testDecryptByInputStreamAndCustom() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        // 源文件
        FileInputStream source = new FileInputStream("C:\\Users\\Thinkpad\\Desktop\\加密-预览20M.pdf");
        // 创建SM4算法
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
        byte[] key = Base64.getDecoder().decode("aW6sIKDsH4U9QIXjIshTHw==");
        Key sm4Key = new SecretKeySpec(key, "SM4");
        cipher.init(Cipher.DECRYPT_MODE, sm4Key);
        AesCryptoCipher aesCryptoCipher = new AesCryptoCipher(cipher, Cipher.DECRYPT_MODE);

        // 包装成解密流, 使用SM4解密
        CipherInputStream cipherInputStream = new CipherInputStream(source, aesCryptoCipher);
        // 输出
        FileOutputStream outputStream = new FileOutputStream("C:\\Users\\Thinkpad\\Desktop\\解密-预览20M.pdf");
        write(cipherInputStream, outputStream);
        outputStream.close();
        cipherInputStream.close();
    }

    public void write(InputStream input, OutputStream output) throws IOException {
        byte[] buffer = new byte[4096];
        int n;
        while (-1 != (n = input.read(buffer))) {
            output.write(buffer, 0, n);
        }
    }
}
```
# 有几点要说
- CipherOutputStream 暂时只支持加密功能，不支持解密，后续可能会加上改功能，
  暂时推荐使用 CipherInputStream
- qq群: 1021884609