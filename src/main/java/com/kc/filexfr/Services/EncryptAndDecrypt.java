package com.kc.filexfr.Services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;

@Service
@Slf4j
public class EncryptAndDecrypt implements ApplicationRunner {

    public void doDecrypt() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] bytes = Files.readAllBytes(Paths.get("./FILES/ED.key"));
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pvt = kf.generatePrivate(ks);

        byte[] bytes1 = Files.readAllBytes(Paths.get("./FILES/b.enc"));
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, pvt, oaepParams);
        byte[] decrypted = cipher.doFinal(bytes1);
        log.info("decrypted is : " + Arrays.toString(decrypted));
    }

    public void test() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024, random);
        KeyPair keyPair = keyGen.generateKeyPair();

        /* constant 117 is a public key size - 11 */
        byte[] plaintext = new byte[117];
        random.nextBytes(plaintext);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] ciphertext = cipher.doFinal(plaintext);
        System.out.println(plaintext.length + " becomes " + ciphertext.length);
    }

    public void test1() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        byte[] input = "abc".getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        //Cipher cipher = Cipher.getInstance("RSA/ECB/NOPADDING");
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048, random);

        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();

        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + new String(cipherText));

        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + new String(plainText));

        //=======

        byte[] bytes = Files.readAllBytes(Paths.get("./FILES/ED1.key"));
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pvt = kf.generatePrivate(ks);

        byte[] bytes1 = Files.readAllBytes(Paths.get("./FILES/b.enc"));
        log.info("bytes1 size is : " + bytes1.length);
        //byte[] ibuf = "77,23,248,106,145,79,51,72,174,220,104,214,0,229,60,189,29,71,8,11,193,160,246,250,177,223,156,232,219,231,12,204,22,3,51,218,221,17,47,124,26,253,60,14,201,92,81,248,240,11,205,95,238,134,176,247,20,248,194,219,201,103,128,37,5,216,245,151,242,78,123,213,85,43,203,252,206,34,5,81,32,239,35,148,255,46,98,184,200,117,140,118,130,119,8,109,70,243,224,194,127,223,226,199,49,235,126,92,189,242,188,165,1,142,44,218,246,160,98,29,189,79,146,95,85,33,243,86,241,128,141,31,19,34,151,254,160,193,76,132,19,202,214,253,72,129,29,93,242,103,140,151,124,38,185,118,126,43,234,226,26,154,80,81,69,210,226,60,26,223,20,187,50,212,57,240,209,101,130,15,215,14,51,149,201,7,234,146,206,38,85,104,169,206,160,245,121,70,56,123,87,1,201,73,206,37,138,1,245,45,218,34,254,205,166,21,31,163,139,24,228,78,247,173,212,6,21,52,248,4,26,163,58,196,172,199,30,248,211,197,200,145,137,200,118,91,238,154,196,22,10,107,149,140,85,17";
        Cipher cipher1 = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        cipher1.init(Cipher.DECRYPT_MODE, pvt, oaepParams);
        //cipher.init(Cipher.DECRYPT_MODE, pvt);
        byte[] decrypted = cipher1.doFinal(bytes1);
        log.info("decrypted is : " + Arrays.toString(decrypted));
    }

    public void doGenkey() throws java.security.NoSuchAlgorithmException, JOSEException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kp.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) kp.getPublic();
        log.info("rsaPrivateKey.getEncoded is : " + rsaPrivateKey.getEncoded());
        log.info("rsaPrivateKey.getFormat() is : " + rsaPrivateKey.getFormat());
        try (FileOutputStream out = new FileOutputStream("./FILES/ED.key")) {
            out.write(kp.getPrivate().getEncoded());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        try (FileOutputStream out = new FileOutputStream("./FILES/ED.pub")) {
            out.write(kp.getPublic().getEncoded());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        RSAKey jwkRsaPublicKey = new RSAKey.Builder(rsaPublicKey).build();
        log.info("jwkRsaPublicKey is : " + jwkRsaPublicKey);
        RSAKey jwk = new RSAKey.Builder(rsaPublicKey)
                .privateKey(rsaPrivateKey)
                .build();
        log.info("ddd" + jwkRsaPublicKey.toPublicJWK());
        log.info("public key " + jwk.toPublicJWK());
        log.info("private key " + jwk);



//        log.info("encoded : " + jwk.toRSAPublicKey().getEncoded());
//        log.info("format is : " + jwk.toRSAPublicKey().getFormat());
//        log.info("encoded : " + jwk.toRSAPrivateKey().getEncoded());
//        log.info("format is : " + jwk.toRSAPublicKey().getFormat());
//        log.info("RSApublic key is : " + jwk.toPublicKey());
    }

//    public void decrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
//        byte[] bytes = Files.readAllBytes(Paths.get("./FILES/private.pem"));
//        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        PrivateKey pvt = kf.generatePrivate(ks);
//
//        byte[] ibuf = "77,23,248,106,145,79,51,72,174,220,104,214,0,229,60,189,29,71,8,11,193,160,246,250,177,223,156,232,219,231,12,204,22,3,51,218,221,17,47,124,26,253,60,14,201,92,81,248,240,11,205,95,238,134,176,247,20,248,194,219,201,103,128,37,5,216,245,151,242,78,123,213,85,43,203,252,206,34,5,81,32,239,35,148,255,46,98,184,200,117,140,118,130,119,8,109,70,243,224,194,127,223,226,199,49,235,126,92,189,242,188,165,1,142,44,218,246,160,98,29,189,79,146,95,85,33,243,86,241,128,141,31,19,34,151,254,160,193,76,132,19,202,214,253,72,129,29,93,242,103,140,151,124,38,185,118,126,43,234,226,26,154,80,81,69,210,226,60,26,223,20,187,50,212,57,240,209,101,130,15,215,14,51,149,201,7,234,146,206,38,85,104,169,206,160,245,121,70,56,123,87,1,201,73,206,37,138,1,245,45,218,34,254,205,166,21,31,163,139,24,228,78,247,173,212,6,21,52,248,4,26,163,58,196,172,199,30,248,211,197,200,145,137,200,118,91,238,154,196,22,10,107,149,140,85,17";
//        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
//        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
//        cipher.init(Cipher.DECRYPT_MODE, pvt, oaepParams);
//        byte[] decrypted = cipher.doFinal(encryptedBytes);
//    }

    public void test2() throws IOException, ParseException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, IllegalBlockSizeException {
        //RSA KEK
        String fileName = "test.pdf";
        SecureRandom srandom = new SecureRandom();
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey skey = kgen.generateKey();
        //IV
        byte[] iv = new byte[128/8];
        srandom.nextBytes(iv);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        JWKSet publicKeys = JWKSet.load(new File("./FILES/pub.json"));
        RSAKey rsaKey = (RSAKey) publicKeys.getKeys().get(0);
        RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
        byte[] bytes = rsaPublicKey.getEncoded();

        //byte[] bytes = Files.readAllBytes(Paths.get("./FILES/ED1.pub"));
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(ks);

        try (FileOutputStream out = new FileOutputStream("./FILES/" + fileName + ".enc")) {
            Cipher cipher1 = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
            cipher1.init(Cipher.ENCRYPT_MODE, pub, oaepParams);
            //cipher.init(Cipher.DECRYPT_MODE, pvt);
            byte[] encryptedKek = cipher1.doFinal("asdfsd".getBytes());
            out.write(encryptedKek);
            //byte[] encryptedKek = cipher1.doFinal("kasdfds".getBytes());
            log.info("encryptedKek length is : " + encryptedKek.length);

            //Encrypt Data
            try (FileInputStream in = new FileInputStream("./FILES/" + fileName)) {
                //Cipher ci = Cipher.getInstance("AES/CBC/NoPadding");
                //possible for wrong decrypt
                Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
                ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
                processFile(ci, in, out);
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    static private void processFile(Cipher ci,InputStream in,OutputStream out)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException
    {
        byte[] ibuf = new byte[1024];
        int len;
        while ((len = in.read(ibuf)) != -1) {
            byte[] obuf = ci.update(ibuf, 0, len);
            if ( obuf != null ) out.write(obuf);
        }
        byte[] obuf = ci.doFinal();
        if ( obuf != null ) out.write(obuf);
    }

//    public void test3() {
//        try (FileInputStream in = new FileInputStream("./FILES/" + fileName)) {
//            //Cipher ci = Cipher.getInstance("AES/CBC/NoPadding");
//            //possible for wrong decrypt
//            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
//            ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
//            processFile(ci, in, out);
//        }
//    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.info("calling...");
        doGenkey();
        //doDecrypt();
        //test();
        //test1();
        //test2();
        //test3();
        //decrypt();
    }
}
