package ca;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.EnumSet;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class RootCA {

    // Método que genera claves RSA inyectando un generador de números aleatorios fuerte
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = SecureRandom.getInstanceStrong(); // Hardening: Entropía fuerte
        generator.initialize(4096, secureRandom); // Tamaño de la clave
        return generator.generateKeyPair();
    }

    /* Método para generar el certificado raíz con extensiones X.509 v3 */
    public static X509Certificate generateRootCertificate(KeyPair keyPair) throws Exception {
        
        // Se define el Distinguished Name (DN) con coherencia corporativa/académica
        X500Name issuer = new X500Name("CN=RootCA,O=Universidad,OU=Ciberseguridad,C=EC");

        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + (20L * 365 * 24 * 60 * 60 * 1000)); // 20 años

        // Identificador único generado criptográficamente seguro
        BigInteger serial = new BigInteger(64, new SecureRandom());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, 
                serial, 
                notBefore, 
                notAfter, 
                issuer, 
                keyPair.getPublic()
        );

        // INYECCIÓN DE EXTENSIONES CRÍTICAS PARA UNA CA
        // 1. Basic Constraints: Define que es una CA
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        
        // 2. Key Usage: Define que la clave se usa para firmar certificados y CRLs
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        // Firma del certificado utilizando SHA-512
        ContentSigner signer = new JcaContentSignerBuilder("SHA512withRSA").build(keyPair.getPrivate());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    public static void saveRootCA(KeyPair keyPair, X509Certificate certificate) throws Exception {
        Path folderPath = Paths.get("certificates");
        
        if (!Files.exists(folderPath)) {
            Files.createDirectories(folderPath);
        }

        // Guardar clave privada en formato PEM
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" 
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded()) 
                + "\n-----END PRIVATE KEY-----";
        
        Path keyPath = folderPath.resolve("root-ca.key");
        Files.writeString(keyPath, privateKeyPem);

        // HARDENING: Aplicar permisos chmod 600 a la clave privada (Solo lectura/escritura para el propietario)
        try {
            Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(keyPath, perms);
            System.out.println("[Hardening] Permisos chmod 600 aplicados a root-ca.key");
        } catch (UnsupportedOperationException e) {
            System.out.println("[Advertencia] El sistema operativo actual no soporta permisos POSIX nativos. Se omitió chmod 600.");
        }

        // Guardar certificado en formato PEM
        String certPem = "-----BEGIN CERTIFICATE-----\n" 
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded()) 
                + "\n-----END CERTIFICATE-----";
        
        Path certPath = folderPath.resolve("root-ca.crt");
        Files.writeString(certPath, certPem);

        System.out.println("Artefactos criptográficos generados y guardados exitosamente en /certificates");
    }
}