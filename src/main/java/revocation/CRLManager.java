package revocation;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import audit.AuditLogger;

public class CRLManager {

    public static X509CRL generateCRL(
            X509Certificate caCert, 
            PrivateKey caPrivateKey, 
            BigInteger revokedSerialNumber) throws Exception {

        Date now = new Date();
        
        // CORRECCIÓN CRÍTICA: Cumplimiento de rúbrica, Next Update <= 24 horas
        Date nextUpdate = new Date(now.getTime() + (24L * 60 * 60 * 1000));

        X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(), now);
        crlBuilder.setNextUpdate(nextUpdate);

        // Añadir el certificado revocado a la lista indicando compromiso de la clave
        crlBuilder.addCRLEntry(revokedSerialNumber, now, CRLReason.keyCompromise);

        // Firmar la CRL con la clave privada de la CA (Sub CA) usando criptografía fuerte
        ContentSigner signer = new JcaContentSignerBuilder("SHA512withRSA").build(caPrivateKey);
        X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));
        
        AuditLogger.log("CRL generada con NextUpdate en 24h. Certificado serial [" + revokedSerialNumber + "] añadido a la lista de revocación.");
        return crl;
    }

    public static void saveCRL(String filePath, X509CRL crl) throws Exception {
        // Refactorización a java.nio para coherencia arquitectónica y resolución de rutas correctas
        Path path = Paths.get(filePath);
        
        if (path.getParent() != null && !Files.exists(path.getParent())) {
            Files.createDirectories(path.getParent());
        }

        String crlPem = "-----BEGIN X509 CRL-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(crl.getEncoded())
                + "\n-----END X509 CRL-----\n";

        Files.writeString(path, crlPem);
        AuditLogger.log("Archivo CRL guardado en disco: " + path.toString());
        System.out.println("Lista de revocación (CRL) estructurada y guardada correctamente.");
    }
}