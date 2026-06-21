package ca;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Calendar;
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

public class SubCA {

    public static KeyPair generateSubCAKeys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = SecureRandom.getInstanceStrong(); // Hardening: Entropía fuerte
        gen.initialize(4096, secureRandom);
        return gen.generateKeyPair();
    }

    // Se añade rootCert como parámetro para poder construir el ca-chain.pem
    public static void saveSubCA(KeyPair keyPair, X509Certificate subCertificate, X509Certificate rootCertificate) throws Exception {
        Path folderPath = Paths.get("certificates");
        if (!Files.exists(folderPath)) {
            Files.createDirectories(folderPath);
        }

        // 1. Guardar y asegurar Sub CA Key
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----";

        Path keyPath = folderPath.resolve("sub-ca.key");
        Files.writeString(keyPath, privateKeyPem);

        // HARDENING: Aplicar permisos chmod 600
        try {
            Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(keyPath, perms);
            System.out.println("[Hardening] Permisos chmod 600 aplicados a sub-ca.key");
        } catch (UnsupportedOperationException e) {
            System.out.println("[Advertencia] SO no soporta permisos POSIX nativos.");
        }

        // 2. Guardar Sub CA Certificate
        String subCertPem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(subCertificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";

        Path certPath = folderPath.resolve("sub-ca.crt");
        Files.writeString(certPath, subCertPem);
        System.out.println("Sub CA Certificate guardado exitosamente.");

        // 3. Generar ca-chain.pem (Requerido por la rúbrica)
        String rootCertPem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(rootCertificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";

        Path chainPath = folderPath.resolve("ca-chain.pem");
        // Escribimos primero el de la SubCA y luego el de la RootCA (Orden estándar de las cadenas TLS)
        Files.writeString(chainPath, subCertPem);
        Files.writeString(chainPath, rootCertPem, StandardOpenOption.APPEND);
        System.out.println("Cadena de confianza (ca-chain.pem) generada exitosamente.");
    }

    public static X509Certificate generateSubCertificate(
            KeyPair subKeys,
            PrivateKey rootPrivateKey,
            X509Certificate rootCert) throws Exception {

        X500Name issuer = new X500Name(rootCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=SubCA,OU=Unidad TIC,O=Universidad,C=EC");

        Date notBefore = new Date();
        
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(notBefore);
        calendar.add(Calendar.YEAR, 5); // Duración de 5 años según secuencia
        Date notAfter = calendar.getTime();

        BigInteger serial = new BigInteger(64, new SecureRandom());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                subKeys.getPublic());

        // EXTENSIONES CRÍTICAS
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA512withRSA").build(rootPrivateKey);

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}