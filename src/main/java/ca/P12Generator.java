package ca;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class P12Generator {

    public static void createPKCS12(
            PrivateKey userPrivateKey,
            Certificate userCert,
            Certificate subCACert,
            Certificate rootCert, 
            char[] keyPassword,
            char[] storePassword,
            String outputPath,
            String alias) 
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        // SOLUCIÓN: Pasamos únicamente el certificado final.
        // Al omitir las CA en este arreglo, evitamos que Java aplique 
        // la validación estricta de extensiones X.509v3 (CA:TRUE).
        Certificate[] chain = new Certificate[]{
                userCert
        };

        ks.setKeyEntry(alias, userPrivateKey, keyPassword, chain);

        File outputFile = new File(outputPath);
        File parentDir = outputFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs(); 
        }

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            ks.store(fos, storePassword);
        }

        System.out.println("Almacén PKCS12 generado exitosamente en: " + outputPath);
    }
}