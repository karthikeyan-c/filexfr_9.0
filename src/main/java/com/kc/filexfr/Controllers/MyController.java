package com.kc.filexfr.Controllers;

import com.kc.filexfr.Services.MyZip;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import net.lingala.zip4j.exception.ZipException;
import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.MalformedURLException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@RestController
@Slf4j
public class MyController {
    private final MyZip myZip;
    private final String fileBasePath = "/Users/karthikeyanc/Documents/SRC/filexfr/FILES/";
    private final String contentType = "application/octet-stream";
    private final String zipFileName = "final.zip";

    public MyController(MyZip myZip) {
        this.myZip = myZip;
    }

    @GetMapping("/test")
    public String fileDownload() throws ZipException {
        myZip.zip();
        return "take the file";
    }

//    @PostMapping("/upload")
//    public ResponseEntity uploadToLocalFileSystem(@RequestParam("file") MultipartFile file,
//                                                  @RequestParam("iv") String iv,
//                                                  @RequestParam("wrappedKey") MultipartFile wrappedKey) {
//        log.info("file is : " + file);
//        log.info("iv is : " + iv);
//        log.info("wrappedKey is : " + wrappedKey);
//
//        String fileName = StringUtils.cleanPath(file.getOriginalFilename());
//        String wfileName = StringUtils.cleanPath(wrappedKey.getOriginalFilename());
//        Path path = Paths.get(fileBasePath + fileName);
//        Path wrappedKeyPath = Paths.get(fileBasePath + wfileName);
//        try {
//            Files.copy(file.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
//            Files.copy(wrappedKey.getInputStream(), wrappedKeyPath, StandardCopyOption.REPLACE_EXISTING);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        String fileDownloadUri = ServletUriComponentsBuilder.fromCurrentContextPath()
//                .path("/download/")
//                .path(fileName)
//                .toUriString();
//        return ResponseEntity.ok(fileDownloadUri);
//    }

//    public RSAPrivateKey readPrivateKey(File file) throws Exception {
//        KeyFactory factory = KeyFactory.getInstance("RSA");
//
//        try (FileReader keyReader = new FileReader(file);
//             PemReader pemReader = new PemReader(keyReader)) {
//
//            PemObject pemObject = pemReader.readPemObject();
//            byte[] content = pemObject.getContent();
//            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
//            return (RSAPrivateKey) factory.generatePrivate(privKeySpec);
//        }
//    }

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

    @PostMapping("/upload")
    public ResponseEntity uploadToLocalFileSystem(@RequestParam("file") MultipartFile file,
                                                  @RequestParam("iv") String ivString,
                                                  @RequestParam("wrappedKey") MultipartFile wrappedKey) {
        log.info("file is : " + file);
        log.info("iv is : " + ivString);
        log.info("wrappedKey is : " + wrappedKey);

        String fileName = StringUtils.cleanPath(file.getOriginalFilename());
        String wfileName = StringUtils.cleanPath(wrappedKey.getOriginalFilename());
        Path path = Paths.get(fileBasePath + fileName);
        Path wrappedKeyPath = Paths.get(fileBasePath + wfileName);
        try {
            Files.copy(file.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
            Files.copy(wrappedKey.getInputStream(), wrappedKeyPath, StandardCopyOption.REPLACE_EXISTING);
            log.info("wrappedKey.getInputStream() is : " + wrappedKey.getInputStream());

            //byte[] bytes = Files.readAllBytes(Paths.get("./FILES/private.pem"));
//            String bytes2 = Files.readString(Paths.get("./FILES/private.pem"), Charset.defaultCharset());
//
//            String privateKeyPEM = bytes2
//                    .replace("-----BEGIN PRIVATE KEY-----", "")
//                    .replaceAll(System.lineSeparator(), "")
//                    .replace("-----END PRIVATE KEY-----", "");
//
//            byte[] encoded = Base64.decodeBase64(privateKeyPEM);
//
//            RSAPrivateKey rsaPrivateKey = readPrivateKey(new File("./FILES/private.pem"));

            byte[] bytes = Files.readAllBytes(Paths.get("./FILES/ED1.key"));
            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pvt = kf.generatePrivate(ks);

            byte[] bytes1 = Files.readAllBytes(Paths.get("./FILES/a.wk"));
            log.info("bytes1 size is : " + bytes1.length);
            //byte[] ibuf = "77,23,248,106,145,79,51,72,174,220,104,214,0,229,60,189,29,71,8,11,193,160,246,250,177,223,156,232,219,231,12,204,22,3,51,218,221,17,47,124,26,253,60,14,201,92,81,248,240,11,205,95,238,134,176,247,20,248,194,219,201,103,128,37,5,216,245,151,242,78,123,213,85,43,203,252,206,34,5,81,32,239,35,148,255,46,98,184,200,117,140,118,130,119,8,109,70,243,224,194,127,223,226,199,49,235,126,92,189,242,188,165,1,142,44,218,246,160,98,29,189,79,146,95,85,33,243,86,241,128,141,31,19,34,151,254,160,193,76,132,19,202,214,253,72,129,29,93,242,103,140,151,124,38,185,118,126,43,234,226,26,154,80,81,69,210,226,60,26,223,20,187,50,212,57,240,209,101,130,15,215,14,51,149,201,7,234,146,206,38,85,104,169,206,160,245,121,70,56,123,87,1,201,73,206,37,138,1,245,45,218,34,254,205,166,21,31,163,139,24,228,78,247,173,212,6,21,52,248,4,26,163,58,196,172,199,30,248,211,197,200,145,137,200,118,91,238,154,196,22,10,107,149,140,85,17";
            Cipher cipher1 = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
            cipher1.init(Cipher.DECRYPT_MODE, pvt, oaepParams);
            //cipher.init(Cipher.DECRYPT_MODE, pvt);
            byte[] decryptedKey = cipher1.doFinal(bytes1);
            log.info("decryptedKey length is : " + decryptedKey.length);

            ByteBuffer bb = ByteBuffer.wrap(decryptedKey);
            byte[] aesKey = new byte[32];
            byte[] iv = new byte[16];
            bb.get(aesKey, 0, aesKey.length);
            bb.get(iv, 0, iv.length);

            //Decrypt the file
            //AES Key
            SecretKeySpec skey = null;
            skey = new SecretKeySpec(aesKey, "AES");

            //IV
            //byte[] iv = new byte[128/8];
            //iv = ivString;
            log.info("iv length is : "+ iv.length);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            //Data
            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ci.init(Cipher.DECRYPT_MODE, skey, ivspec);

            try (FileInputStream in = new FileInputStream("./FILES/a.zip.enc")) {
                try (FileOutputStream out = new FileOutputStream("./FILES/output.pdf")) {
                    processFile(ci, in, out);
                }
            }
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        String fileDownloadUri = ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/download/")
                .path(fileName)
                .toUriString();
        return ResponseEntity.ok(fileDownloadUri);
    }

    @GetMapping("/download/{fileName:.+}")
    public ResponseEntity downloadFileFromLocal(@PathVariable String fileName) {
        Path path = Paths.get(fileBasePath + fileName);
        Resource resource = null;
        try {
            resource = new UrlResource(path.toUri());
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                .body(resource);
    }

    @GetMapping(value = "/zip-download", produces="application/zip")
    public void zipDownload(@RequestParam List<String> name, HttpServletResponse response) throws IOException {
        ZipOutputStream zipOut = new ZipOutputStream(response.getOutputStream());
        for (String fileName : name) {
            FileSystemResource resource = new FileSystemResource(fileBasePath + fileName);
            ZipEntry zipEntry = new ZipEntry(resource.getFilename());
            zipEntry.setSize(resource.contentLength());
            zipOut.putNextEntry(zipEntry);
            StreamUtils.copy(resource.getInputStream(), zipOut);
            zipOut.closeEntry();
        }
        zipOut.finish();
        zipOut.close();
        response.setStatus(HttpServletResponse.SC_OK);
        response.addHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + zipFileName + "\"");
    }

    @GetMapping(value = "/enc-zip-download", produces="application/zip")
    public ResponseEntity<Resource> encZipDownload(@RequestParam List<String> name, HttpServletResponse response) throws IOException {
        String stagingFile = myZip.encZip(name,response);
        log.info("stagingFile is controller : " + stagingFile);

        Path path = Paths.get(stagingFile);
        Resource resource = null;
        try {
            resource = new UrlResource(path.toUri());
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                .body(resource);

    }

    @PostMapping(value = "/enc-zip-download", produces="application/zip")
    public ResponseEntity<Resource> encZipDownloadPost(@RequestParam List<String> name, HttpServletResponse response) throws IOException {
        String stagingFile = myZip.encZip(name,response);
        log.info("stagingFile is controller : " + stagingFile);

        Path path = Paths.get(stagingFile);
        Resource resource = null;
        try {
            resource = new UrlResource(path.toUri());
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                .body(resource);
    }

//    @PostMapping("/download/{fileName:.+}")
//    public ResponseEntity postDownloadFileFromLocal(@PathVariable String fileName) {
//        Path path = Paths.get(fileBasePath + fileName);
//        Resource resource = null;
//        try {
//            resource = new UrlResource(path.toUri());
//        } catch (MalformedURLException e) {
//            e.printStackTrace();
//        }
//        return ResponseEntity.ok()
//                .contentType(MediaType.parseMediaType(contentType))
//                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
//                .body(resource);
//    }

    @PostMapping("/download/{fileName:.+}")
    public ResponseEntity postDownloadFileFromLocal(@PathVariable String fileName) {
        SecureRandom srandom = new SecureRandom();

        //Path path = Paths.get(fileBasePath + fileName);
        Path path = Paths.get("./FILES/" + fileName + ".enc");

        Resource resource = null;
        try {
            resource = new UrlResource(path.toUri());

            //Encrypt the file with AES
            //Key
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey skey = kgen.generateKey();
            //IV
            byte[] iv = new byte[128/8];
            srandom.nextBytes(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            //Encrypt using RSA
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            //Possible for wrong key
            log.info("skey.getEncoded() is: " + Arrays.toString(skey.getEncoded()));
            log.info("skey.getEncoded() iszie is: " + skey.getEncoded().length);
            log.info("iv lenght is : " + iv.length);
            outputStream.write(skey.getEncoded());
            outputStream.write(iv);
            byte[] kek = outputStream.toByteArray();

            //RSA KEK
            JWKSet publicKeys = JWKSet.load(new File("./FILES/pub.json"));
            RSAKey rsaKey = (RSAKey) publicKeys.getKeys().get(0);
            log.info("rsaKey is : " + rsaKey);
            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
            byte[] bytes = rsaPublicKey.getEncoded();
            log.info(" bytes is " + Arrays.toString(bytes));

            //byte[] bytes = Files.readAllBytes(Paths.get("./FILES/ED1.pub"));
            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(ks);

            try (FileOutputStream out = new FileOutputStream("./FILES/" + fileName + ".enc")) {
                Cipher cipher1 = Cipher.getInstance("RSA/ECB/OAEPPadding");
                OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
                cipher1.init(Cipher.ENCRYPT_MODE, pub, oaepParams);
                //cipher.init(Cipher.DECRYPT_MODE, pvt);
                byte[] encryptedKek = cipher1.doFinal(kek);
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
                }
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                .body(resource);
    }
}
