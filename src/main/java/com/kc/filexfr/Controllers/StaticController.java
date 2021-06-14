package com.kc.filexfr.Controllers;

import com.kc.filexfr.Entity.fileDetails;
import com.kc.filexfr.Entity.fileDetailsKey;
import com.kc.filexfr.Entity.reqDetails;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.Synchronized;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import com.kc.filexfr.Repository.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
import java.util.*;

@Controller
@RequestMapping
@Slf4j
public class StaticController {
    @Autowired
    private reqDetailsRepository reqDetailsRepository;
    @Autowired
    private fileDetailsRepository fileDetailsRepository;

    private final String contentType = "application/octet-stream";
    private final String fileBasePath = "./STAGING/";

    @GetMapping("/landing/{mode}")
    public String landing(@PathVariable Character mode,
                          Model model) {
        UUID reqUUID = UUID.randomUUID();
        UUID fileUUID = UUID.randomUUID();
        model.addAttribute("name", "imagek2122");
        model.addAttribute("reqUUID", reqUUID);
        //Get the value from secure link. check upload or download.
        log.info("processing1 ..." + reqUUID);
        //Request Details
        reqDetails request = new reqDetails(
                reqUUID.toString(),
                mode,
                fileUUID.toString(), "", "", "", "", 1);
        reqDetails byId = reqDetailsRepository.save(request);
//        //File Details
//        List<fileDetails> fileDetailsList = new ArrayList<>();
//        fileDetailsList.add(new fileDetails(fileUUID.toString(),
//                "1.png",
//                "/Users/karthikeyanc/Documents/SRC/filexfr/FILES",
//                new Date()));
//        fileDetailsRepository.saveAll(fileDetailsList);
        return "landing";
    }

    @PostMapping("/request/{reqUUID}")
    public String listOrBrowse(@RequestParam("otp") String otp,
                               @RequestParam("publicKey") String publicKey,
                               @RequestParam UUID reqId,
                               @PathVariable("reqUUID") UUID reqUUID,
                               Model model) throws ParseException, JOSEException, NoSuchAlgorithmException {
        model.addAttribute("name", "imagek2122");
        model.addAttribute("reqUUID", reqUUID);
        log.info("processing2 ..." + reqUUID);
        log.info("reqId is " + reqId);
        reqDetails req = reqDetailsRepository.getById(reqUUID.toString());
        if (req.getReqType().equals('U')) {
            //Generate Key pair and store private.
            String pubKey = generateKeyPair(req);
            model.addAttribute("publicKey", pubKey);
            return "encupload";
        } else {
            if (!publicKey.isEmpty()) {
                log.info("received public key is " + publicKey);
                req.setCryptoKey(publicKey);
                reqDetailsRepository.save(req);

                reqDetails uReq = reqDetailsRepository.getById(reqId.toString());
                model.addAttribute("files", fileDetailsRepository.findAllByFileId(uReq.getFileId()));
            }
            return "encdownload";
        }
    }

    private String generateKeyPair(reqDetails req) throws NoSuchAlgorithmException, JOSEException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kp.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) kp.getPublic();

        RSAKey jwk = new RSAKey.Builder(rsaPublicKey)
                .privateKey(rsaPrivateKey)
                .build();

        req.setCryptoKey(jwk.toString());
        reqDetailsRepository.save(req);

        return jwk.toPublicJWK().toString();
    }

    @PostMapping("/encupload/{reqUUID}")
    public ResponseEntity encUpload(@RequestParam("file") MultipartFile file,
                                    @RequestParam("iv") String ivString,
                                    @RequestParam("chunkNo") Integer chunk,
                                    @PathVariable("reqUUID") UUID reqUUID,
                                    @RequestParam("wrappedKey") MultipartFile wrappedKey) throws IOException, ParseException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException {
        String fileName = StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename()));
        log.info("fileName3 ..." + fileName);
        log.info("processing3 ..." + reqUUID);
        log.info("chunk ..." + chunk);

        //Fetch Request details.
        reqDetails req = reqDetailsRepository.getById(reqUUID.toString());

        if (chunk==1) {
            fileDetailsRepository.save(new fileDetails(
                    req.getFileId(),
                    fileName,
                    fileBasePath + fileName,
                    new Date()
            ));
        }
        log.info("D1 ..." + chunk);
        String privateKey = "{\"keys\": [" + req.getCryptoKey() + "]}";
        Path tempFile = Files.createTempFile(null, null);
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(tempFile.toFile()))) {
            bw.write(privateKey);
        }
        log.info("D2 ..." + chunk);
        //RSA KEK
        JWKSet privateKeys = JWKSet.load(new File(String.valueOf(tempFile)));
        RSAKey rsaKey = (RSAKey) privateKeys.getKeys().get(0);
        RSAPrivateKey rsaPrivateKey = rsaKey.toRSAPrivateKey();
        byte[] bytes = rsaPrivateKey.getEncoded();
        log.info("D3 ..." + chunk);
        try {
            //KEK decryption
            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pvt = kf.generatePrivate(ks);

            byte[] bytes1 = wrappedKey.getInputStream().readAllBytes();
            Cipher cipher1 = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
            cipher1.init(Cipher.DECRYPT_MODE, pvt, oaepParams);
            byte[] decryptedKey = cipher1.doFinal(bytes1);
            log.info("D4 ..." + chunk);
            //Combine KEK and IV
            ByteBuffer bb = ByteBuffer.wrap(decryptedKey);
            byte[] aesKey = new byte[32];
            byte[] iv = new byte[16];
            bb.get(aesKey, 0, aesKey.length);
            bb.get(iv, 0, iv.length);
            log.info("D5 ..." + chunk);
            //Decrypt the file
            //AES Key
            SecretKeySpec skey = null;
            skey = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ci.init(Cipher.DECRYPT_MODE, skey, ivspec);
            log.info("D6 ..." + chunk);
            synchronized(this) {
                InputStream in = file.getInputStream();
                //try (FileOutputStream out = new FileOutputStream(fileBasePath + chunk + ".uploaded." + fileName)) {
                try (FileOutputStream out = new FileOutputStream(fileBasePath + "uploaded." + fileName, true)) {
                    processFile(ci, in, out);
                }
            }
            log.info("D7 ..." + chunk);
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
        log.info("D8 ..." + chunk);
        String fileDownloadUri = ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/download/")
                .path(fileName)
                .toUriString();
        return ResponseEntity.ok(fileDownloadUri);
    }

// working==>
//    @PostMapping("/encupload/{reqUUID}")
//    public ResponseEntity encUpload(@RequestParam("file") MultipartFile file,
//                                    @RequestParam("iv") String ivString,
//                                    @PathVariable("reqUUID") UUID reqUUID,
//                                    @RequestParam("wrappedKey") MultipartFile wrappedKey) throws IOException, ParseException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException {
//        String fileName = StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename()));
//        log.info("fileName3 ..." + fileName);
//        log.info("processing3 ..." + reqUUID);
//
//        //Fetch Request details.
//        reqDetails req = reqDetailsRepository.getById(reqUUID.toString());
//
//        fileDetailsRepository.save(new fileDetails(
//                req.getFileId(),
//                fileName,
//                fileBasePath + fileName,
//                new Date()
//        ));
//
//        String privateKey = "{\"keys\": [" + req.getCryptoKey() + "]}";
//        Path tempFile = Files.createTempFile(null, null);
//        try (BufferedWriter bw = new BufferedWriter(new FileWriter(tempFile.toFile()))) {
//            bw.write(privateKey);
//        }
//
//        //RSA KEK
//        JWKSet privateKeys = JWKSet.load(new File(String.valueOf(tempFile)));
//        RSAKey rsaKey = (RSAKey) privateKeys.getKeys().get(0);
//        RSAPrivateKey rsaPrivateKey = rsaKey.toRSAPrivateKey();
//        byte[] bytes = rsaPrivateKey.getEncoded();
//
//        try {
//            //KEK decryption
//            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
//            KeyFactory kf = KeyFactory.getInstance("RSA");
//            PrivateKey pvt = kf.generatePrivate(ks);
//
//            byte[] bytes1 = wrappedKey.getInputStream().readAllBytes();
//            Cipher cipher1 = Cipher.getInstance("RSA/ECB/OAEPPadding");
//            OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
//            cipher1.init(Cipher.DECRYPT_MODE, pvt, oaepParams);
//            byte[] decryptedKey = cipher1.doFinal(bytes1);
//
//            //Combine KEK and IV
//            ByteBuffer bb = ByteBuffer.wrap(decryptedKey);
//            byte[] aesKey = new byte[32];
//            byte[] iv = new byte[16];
//            bb.get(aesKey, 0, aesKey.length);
//            bb.get(iv, 0, iv.length);
//
//            //Decrypt the file
//            //AES Key
//            SecretKeySpec skey = null;
//            skey = new SecretKeySpec(aesKey, "AES");
//            IvParameterSpec ivspec = new IvParameterSpec(iv);
//            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
//            ci.init(Cipher.DECRYPT_MODE, skey, ivspec);
//
//            InputStream in = file.getInputStream();
//            try (FileOutputStream out = new FileOutputStream(fileBasePath + "uploaded." + fileName)) {
//                processFile(ci, in, out);
//            }
//        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException e) {
//            e.printStackTrace();
//        } catch (InvalidKeyException e) {
//            e.printStackTrace();
//        } catch (InvalidAlgorithmParameterException e) {
//            e.printStackTrace();
//        } catch (IllegalBlockSizeException e) {
//            e.printStackTrace();
//        } catch (BadPaddingException e) {
//            e.printStackTrace();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        String fileDownloadUri = ServletUriComponentsBuilder.fromCurrentContextPath()
//                .path("/download/")
//                .path(fileName)
//                .toUriString();
//        return ResponseEntity.ok(fileDownloadUri);
//    }

    static private void processFile(Cipher ci, InputStream in, OutputStream out)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException {
        byte[] ibuf = new byte[1024];
        int len;
        while ((len = in.read(ibuf)) != -1) {
            byte[] obuf = ci.update(ibuf, 0, len);
            if (obuf != null) out.write(obuf);
        }
        byte[] obuf = ci.doFinal();
        if (obuf != null) out.write(obuf);
    }

    static private void processFileChunk(Cipher ci, InputStream in, OutputStream out, Integer chunk)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException {

        //                        int len;
//                        int count=0;
//                        int scount = (chunk-1)*6;
//                        int fcount = chunk*6;
//                        while ((len = in.read(buffer)) > -1 ) {
//                            count++;
//                            log.info("consol ==> " + chunk + count + scount + fcount + len);
//                            if(count<=scount) continue;
//                            //baos.write(buffer, (chunk -1) * 3000000, len);
//                            if (count<=fcount) {
//                                baos.write(buffer,0,len);
//                            } else break;
//                        }
        byte[] ibuf = new byte[1000];
        int len;

        //Chunk
        int count=0;
        int scount = (chunk-1)*(12*100*1000);
        int fcount = chunk*(12*100*1000);

        while ((len = in.read(ibuf)) != -1) {
            count++;
            //log.info("consol ==> " + chunk + count + scount + fcount + len);
            if(count<=scount) continue;
            if (count<=fcount) {
                byte[] obuf = ci.update(ibuf, 0, len);
                if (obuf != null) out.write(obuf);
            } else break;
        }

        byte[] obuf = ci.doFinal();
        if (obuf != null) out.write(obuf);
    }

    @PostMapping("/encdownload/{reqUUID}")
    public ResponseEntity postDownloadFileFromLocal(@RequestParam("fileName") String fileName,
                                                    @PathVariable("reqUUID") UUID reqUUID,
                                                    @RequestParam("chunk") Integer chunk) {
        SecureRandom srandom = new SecureRandom();
        log.info("processing4 ..." + reqUUID);
        log.info("fileName is " + fileName);
        log.info("chunk is" + chunk);
        reqDetails req = reqDetailsRepository.getById(reqUUID.toString());
        //Path path = Paths.get(fileBasePath + fileName);
        Path path = Paths.get(fileBasePath + chunk + "."+ fileName + ".enc");

        Resource resource = null;
        try {
            resource = new UrlResource(path.toUri());

            //Encrypt the file with AES
            //Key
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey skey = kgen.generateKey();
            //IV
            byte[] iv = new byte[128 / 8];
            srandom.nextBytes(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            //Encrypt using RSA
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(skey.getEncoded());
            outputStream.write(iv);
            byte[] kek = outputStream.toByteArray();

            //RSA KEK
            log.info("using public key ===> " + req.getCryptoKey());
            String publicKey = "{\"keys\": [" + req.getCryptoKey() + "]}";
            Path tempFile = Files.createTempFile(null, null);
            try (BufferedWriter bw = new BufferedWriter(new FileWriter(tempFile.toFile()))) {
                bw.write(publicKey);
            }
            JWKSet publicKeys = JWKSet.load(new File(String.valueOf(tempFile)));
            RSAKey rsaKey = (RSAKey) publicKeys.getKeys().get(0);
            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
            byte[] bytes = rsaPublicKey.getEncoded();

            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(ks);

            try (FileOutputStream out = new FileOutputStream(fileBasePath + chunk + "." + fileName + ".enc")) {
                Cipher cipher1 = Cipher.getInstance("RSA/ECB/OAEPPadding");
                OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
                cipher1.init(Cipher.ENCRYPT_MODE, pub, oaepParams);
                byte[] encryptedKek = cipher1.doFinal(kek);
                out.write(encryptedKek);
                log.info("encryptedKek length is : " + encryptedKek.length);
                //Encrypt Data
                synchronized (this){
                    try (FileInputStream in = new FileInputStream(fileBasePath + "uploaded." + fileName)) {
//                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//                        byte[] buffer = new byte[100000000];
//                        int len;
//                        int count=0;
//                        int scount = (chunk-1)*6;
//                        int fcount = chunk*6;
//                        while ((len = in.read(buffer)) > -1 ) {
//                            count++;
//                            log.info("consol ==> " + chunk + count + scount + fcount + len);
//                            if(count<=scount) continue;
//                            //baos.write(buffer, (chunk -1) * 3000000, len);
//                            if (count<=fcount) {
//                                baos.write(buffer,0,len);
//                            } else break;
//                        }
//
//                        baos.flush();
//                        InputStream is1 = new ByteArrayInputStream(baos.toByteArray());

                        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
                        //processFile(ci, in, out);
                        //processFile(ci, in, out);
                        processFileChunk(ci, in, out, chunk);
                    }
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

    // final
//    @PostMapping("/encdownload/{reqUUID}")
//    public ResponseEntity postDownloadFileFromLocal(@RequestParam("fileName") String fileName,
//                                                    @PathVariable("reqUUID") UUID reqUUID) {
//        SecureRandom srandom = new SecureRandom();
//        log.info("processing4 ..." + reqUUID);
//        log.info("fileName is " + fileName);
//        reqDetails req = reqDetailsRepository.getById(reqUUID.toString());
//        //Path path = Paths.get(fileBasePath + fileName);
//        Path path = Paths.get(fileBasePath + fileName + ".enc");
//
//        Resource resource = null;
//        try {
//            resource = new UrlResource(path.toUri());
//
//            //Encrypt the file with AES
//            //Key
//            KeyGenerator kgen = KeyGenerator.getInstance("AES");
//            kgen.init(128);
//            SecretKey skey = kgen.generateKey();
//            //IV
//            byte[] iv = new byte[128 / 8];
//            srandom.nextBytes(iv);
//            IvParameterSpec ivspec = new IvParameterSpec(iv);
//
//            //Encrypt using RSA
//            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//            outputStream.write(skey.getEncoded());
//            outputStream.write(iv);
//            byte[] kek = outputStream.toByteArray();
//
//            //RSA KEK
//            log.info("using public key ===> " + req.getCryptoKey());
//            String publicKey = "{\"keys\": [" + req.getCryptoKey() + "]}";
//            Path tempFile = Files.createTempFile(null, null);
//            try (BufferedWriter bw = new BufferedWriter(new FileWriter(tempFile.toFile()))) {
//                bw.write(publicKey);
//            }
//            JWKSet publicKeys = JWKSet.load(new File(String.valueOf(tempFile)));
//            RSAKey rsaKey = (RSAKey) publicKeys.getKeys().get(0);
//            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
//            byte[] bytes = rsaPublicKey.getEncoded();
//
//            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
//            KeyFactory kf = KeyFactory.getInstance("RSA");
//            PublicKey pub = kf.generatePublic(ks);
//
//            try (FileOutputStream out = new FileOutputStream(fileBasePath + fileName + ".enc")) {
//                Cipher cipher1 = Cipher.getInstance("RSA/ECB/OAEPPadding");
//                OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
//                cipher1.init(Cipher.ENCRYPT_MODE, pub, oaepParams);
//                byte[] encryptedKek = cipher1.doFinal(kek);
//                out.write(encryptedKek);
//                log.info("encryptedKek length is : " + encryptedKek.length);
//
//                //Encrypt Data
//                try (FileInputStream in = new FileInputStream(fileBasePath + "uploaded." + fileName)) {
//                    Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
//                    ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
//                    processFile(ci, in, out);
//                }
//            }
//        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException e) {
//            e.printStackTrace();
//        } catch (InvalidKeyException e) {
//            e.printStackTrace();
//        } catch (InvalidAlgorithmParameterException e) {
//            e.printStackTrace();
//        } catch (IllegalBlockSizeException e) {
//            e.printStackTrace();
//        } catch (BadPaddingException e) {
//            e.printStackTrace();
//        } catch (ParseException e) {
//            e.printStackTrace();
//        } catch (JOSEException e) {
//            e.printStackTrace();
//        }
//        return ResponseEntity.ok()
//                .contentType(MediaType.parseMediaType(contentType))
//                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
//                .body(resource);
//    }
}