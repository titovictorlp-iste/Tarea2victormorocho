import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;

import ca.RootCA;
import ca.SubCA;
import ca.CertificateGenerator; 
import audit.AuditLogger;
import revocation.CRLManager;
import revocation.OCSPManager; // <-- Importación del motor OCSP
import validation.CertificateValidador;
import ca.P12Generator;

public class Main {

    public static void main(String[] args) {
        
        try {
            AuditLogger.log("INICIO DEL PROCESO PKI");

            // 1. ROOT CA
            KeyPair rootKeys = RootCA.generateKeyPair();
            AuditLogger.log("Par de claves Root CA generado");

            X509Certificate rootCert = RootCA.generateRootCertificate(rootKeys);
            AuditLogger.log("Certificado Root CA generado");

            RootCA.saveRootCA(rootKeys, rootCert);
            AuditLogger.log("Root CA almacenada en disco");

            // 2. SUB CA
            KeyPair subKeys = SubCA.generateSubCAKeys();
            AuditLogger.log("Par de claves Sub CA generado");

            X509Certificate subCert = SubCA.generateSubCertificate(
                    subKeys,
                    rootKeys.getPrivate(),
                    rootCert
            );
            AuditLogger.log("Certificado Sub CA firmado por Root CA");

            SubCA.saveSubCA(subKeys, subCert, rootCert);
            AuditLogger.log("Sub CA y Cadena de Confianza almacenadas en disco");

            // 3. CERTIFICADO DE USUARIO
            KeyPair userKeys = CertificateGenerator.generateKeyPair();
            AuditLogger.log("Par de claves Usuario generado");

            X509Certificate userCert = CertificateGenerator.issueUserCertificate(
                    "UsuarioDemo",
                    userKeys.getPublic(),
                    subKeys.getPrivate(),
                    subCert
            );
            AuditLogger.log("Certificado UsuarioDemo emitido");

            CertificateGenerator.saveCertificate("certificates/user-cert.crt", userCert);
            AuditLogger.log("user-cert.crt almacenado");

            AuditLogger.log("Iniciando empaquetado PKCS12 para el usuario...");
            P12Generator.createPKCS12(
                    userKeys.getPrivate(),
                    userCert,
                    subCert,
                    rootCert, 
                    "123456".toCharArray(), 
                    "123456".toCharArray(),
                    "certificates/usuario.p12",
                    "UsuarioDemo"
            );
            AuditLogger.log("Archivo usuario.p12 generado exitosamente");


            // 4. CERTIFICADO DE SERVIDOR (localhost)
            KeyPair serverKeys = CertificateGenerator.generateKeyPair();
            AuditLogger.log("Par de claves Servidor generado");
            
            X509Certificate serverCert = CertificateGenerator.issueUserCertificate(
                    "localhost",
                    serverKeys.getPublic(),
                    subKeys.getPrivate(),
                    subCert
            );
            AuditLogger.log("Certificado Servidor (localhost) emitido");
            
            CertificateGenerator.saveCertificate("certificates/server-cert.crt", serverCert);
            AuditLogger.log("Certificado del servidor almacenado");
            
            P12Generator.createPKCS12(
                    serverKeys.getPrivate(),
                    serverCert,
                    subCert,
                    rootCert,
                    "12345".toCharArray(), 
                    "12345".toCharArray(),
                    "certificates/server.p12",
                    "localhost"
            );
            AuditLogger.log("Archivo PKCS12 de servidor generado");

            
            // 5. GENERACIÓN DE CRL (Lista de Revocación)
            AuditLogger.log("Iniciando proceso de revocación...");
            java.math.BigInteger serialRevocado = userCert.getSerialNumber();
            X509CRL crl = CRLManager.generateCRL(subCert, subKeys.getPrivate(), serialRevocado);
            CRLManager.saveCRL("certificates/sub-ca.crl", crl);
            AuditLogger.log("Lista de Revocación (CRL) almacenada en disco");

            // ========================================================
            // 5.5. PRUEBA OCSP (Requerimiento de Rúbrica)
            // ========================================================
            AuditLogger.log("Iniciando prueba OCSP (< 1s)...");
            System.out.println("\n--- PRUEBA DE PROTOCOLO OCSP ---");
            
            org.bouncycastle.cert.ocsp.OCSPResp ocspResponseRevoked = OCSPManager.checkOCSPStatus(
                    subCert, subKeys.getPrivate(), userCert.getSerialNumber(), crl);
            OCSPManager.printOCSPResponse(ocspResponseRevoked, "Certificado Usuario");

            org.bouncycastle.cert.ocsp.OCSPResp ocspResponseGood = OCSPManager.checkOCSPStatus(
                    subCert, subKeys.getPrivate(), serverCert.getSerialNumber(), crl);
            OCSPManager.printOCSPResponse(ocspResponseGood, "Certificado Servidor");


            // 6. PRUEBA DE VALIDACIÓN DE REVOCACIÓN (CRL)
            AuditLogger.log("Iniciando prueba de validador de certificados (Revocación)...");
            System.out.println("\n--- VALIDACIÓN DE REVOCACIÓN (CRL) ---");
            
            boolean isValid = CertificateValidador.validateFullCertificate(userCert, subCert.getPublicKey(), crl);
            if (!isValid) {
                System.out.println("[✓] ÉXITO: El validador detectó el certificado revocado en la CRL.");
            } else {
                System.out.println("[X] ERROR: El validador falló la comprobación de CRL.");
            }

            // ========================================================
            // 7. SIMULACIÓN DE ATAQUE (Certificado Clonado)
            // ========================================================
            AuditLogger.log("Iniciando simulación de ataque: Creación de certificado clonado...");
            System.out.println("\n--- PRUEBA DE SEGURIDAD: ATAQUE DE CLONACIÓN ---");
            System.out.println("Simulando atacante que intercepta datos y emite un certificado falso...");
            
            // El atacante genera sus propias claves
            KeyPair attackerKeys = RootCA.generateKeyPair(); 
            
            // El atacante intenta emitir un certificado idéntico al del servidor, pero lo firma con SU clave privada, no con la de la SubCA
            X509Certificate clonedCert = CertificateGenerator.issueUserCertificate(
                    "localhost", 
                    serverKeys.getPublic(), // Usa la llave pública original para engañar
                    attackerKeys.getPrivate(), // FIRMA FALSA
                    subCert
            );
            
            AuditLogger.log("Validando certificado clonado contra la clave pública legítima de la SubCA...");
            System.out.println("Intentando autenticar el certificado clonado...");
            
            boolean isClonedValid = CertificateValidador.validateFullCertificate(clonedCert, subCert.getPublicKey(), crl);
            
            if (!isClonedValid) {
                System.out.println("[✓] ÉXITO DE SEGURIDAD: El sistema rechazó el certificado clonado por fallo de firma criptográfica.");
            } else {
                System.out.println("[X] VULNERABILIDAD CRÍTICA: El sistema aceptó un certificado falsificado.");
            }
            // ========================================================

            AuditLogger.log("FIN DEL PROCESO PKI EXITOSO");
            System.out.println("\nArquitectura PKI generada y validada en su totalidad.");

        } catch (Exception e) {
            System.err.println("Ocurrió un error crítico durante la ejecución de la PKI:");
            e.printStackTrace();
        }
    }
}