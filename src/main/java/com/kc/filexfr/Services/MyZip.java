package com.kc.filexfr.Services;

import lombok.extern.slf4j.Slf4j;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import net.lingala.zip4j.model.enums.EncryptionMethod;
import org.springframework.core.io.FileSystemResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StreamUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Service
@Slf4j
public class MyZip {
    private int filename;
    private final String fileBasePath = "/Users/karthikeyanc/Documents/SRC/filexfr/FILES/";
    private final String stagingFile = "/Users/karthikeyanc/Documents/SRC/filexfr/FILES/t.zip";

    public String encZip(List<String> name, HttpServletResponse response) throws IOException {
        ZipParameters zipParameters = new ZipParameters();
        zipParameters.setEncryptFiles(true);
        zipParameters.setEncryptionMethod(EncryptionMethod.AES);
        // Below line is optional. AES 256 is used by default. You can override it to use AES 128. AES 192 is supported only for extracting.
        zipParameters.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);
        List<File> filesToAdd = new ArrayList<>();
        name.forEach( (e) -> {
            filesToAdd.add(new File(fileBasePath + e));
        });
        log.info("filesToAdd is: " + filesToAdd);
        // Later encrypt on the fly. now with staging.
        ZipFile zipFile = new ZipFile(stagingFile, "password".toCharArray());
        zipFile.addFiles(filesToAdd, zipParameters);
        return stagingFile;
    }

    public String zip() throws ZipException {
        ZipParameters zipParameters = new ZipParameters();
        zipParameters.setEncryptFiles(true);
        zipParameters.setEncryptionMethod(EncryptionMethod.AES);
        // Below line is optional. AES 256 is used by default. You can override it to use AES 128. AES 192 is supported only for extracting.
        zipParameters.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);

        List<File> filesToAdd = Arrays.asList(
                new File("/Users/karthikeyanc/Documents/SRC/crypto/java_pgm_zip/t.txt")
        );

        ZipFile zipFile = new ZipFile("/Users/karthikeyanc/Documents/SRC/crypto/java_pgm_zip/t.zip", "password".toCharArray());
        zipFile.addFiles(filesToAdd, zipParameters);
        return "zipped";
    }
}
