package ca;

import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateGenerator {

    // Generar el par de claves para el usuario final (ej. un servidor web o un cliente VPN)
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(4096);
        return gen.generateKeyPair();
    }

    // Emitir el certificado de usuario firmado por la SubCA
    public static X509Certificate issueUserCertificate(
            String commonName,
            PublicKey userPublicKey,
            PrivateKey subCAPrivateKey,
            X509Certificate subCACert) throws Exception {

        // El emisor (Issuer) es la SubCA
        X500Name issuer = new X500Name(subCACert.getSubjectX500Principal().getName());
        
        // El sujeto (Subject) es el usuario final
        X500Name subject = new X500Name("CN=" + commonName + ",O=Universidad,C=EC");

        Date notBefore = new Date();
        
        // Un certificado de usuario final suele tener una validez más corta (ej. 1 año)
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(notBefore);
        calendar.add(Calendar.YEAR, 1);
        Date notAfter = calendar.getTime();

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                userPublicKey);

        // EXTENSIONES CRÍTICAS PARA UN USUARIO FINAL
        // basicConstraints: false significa que este certificado NO puede firmar otros certificados (no es una CA)
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        
        // keyUsage: Define que esta clave se usará para firmas digitales y cifrado de claves (típico para clientes/servidores)
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        // Firmar el certificado usando la clave privada de la SubCA
        ContentSigner signer = new JcaContentSignerBuilder("SHA512withRSA").build(subCAPrivateKey);

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    // Guardar el certificado en la carpeta
    public static void saveCertificate(String fileName, X509Certificate certificate) throws Exception {
        // Formato PEM para el certificado
        String certPem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----";

        try (FileWriter certWriter = new FileWriter(new File(fileName))) {
            certWriter.write(certPem);
            System.out.println("Certificado " + fileName + " guardado correctamente.");
        }
    }

    // ---> NUEVO MÉTODO: Guardar la clave privada en formato PEM <---
    public static void savePrivateKey(String fileName, PrivateKey privateKey) throws Exception {
        // Formato PEM para la clave privada
        String keyPem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(privateKey.getEncoded())
                + "\n-----END PRIVATE KEY-----";

        try (FileWriter keyWriter = new FileWriter(new File(fileName))) {
            keyWriter.write(keyPem);
            System.out.println("Clave privada " + fileName + " guardada correctamente.");
        }
    }
}