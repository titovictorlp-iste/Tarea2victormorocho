package validation;

import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry; // <-- Nuevo import necesario

import audit.AuditLogger;

public class CertificateValidador {

    /**
     * Realiza una validación completa de un certificado: Fechas, Firma y Revocación.
     */
    public static boolean validateFullCertificate(
            X509Certificate certToValidate, 
            PublicKey issuerPublicKey, 
            X509CRL crl) {
        
        AuditLogger.log("Iniciando validación de certificado serial: " + certToValidate.getSerialNumber());

        // 1. Validar Vigencia (Fechas)
        try {
            certToValidate.checkValidity();
            AuditLogger.log("Validación [OK]: El certificado está vigente.");
            System.out.println("[VALIDACIÓN] El certificado está vigente.");
        } catch (CertificateExpiredException e) {
            AuditLogger.log("Validación [ERROR]: El certificado ha expirado.");
            System.err.println("[ERROR] El certificado ha expirado.");
            return false;
        } catch (CertificateNotYetValidException e) {
            AuditLogger.log("Validación [ERROR]: El certificado aún no es válido.");
            System.err.println("[ERROR] El certificado aún no es válido (fecha futura).");
            return false;
        }

        // 2. Validar Firma (Autenticidad)
        try {
            certToValidate.verify(issuerPublicKey);
            AuditLogger.log("Validación [OK]: La firma del certificado es auténtica.");
            System.out.println("[VALIDACIÓN] La firma del certificado es auténtica.");
        } catch (Exception e) {
            AuditLogger.log("Validación [ERROR]: Fallo en la firma criptográfica.");
            System.err.println("[ERROR] Fallo en la validación de la firma: " + e.getMessage());
            return false;
        }

        // 3. Validar Revocación (CRL - Lista Negra)
        // SOLUCIÓN: Buscamos explícitamente el número de serie dentro de la CRL
        if (crl != null) {
            X509CRLEntry revokedEntry = crl.getRevokedCertificate(certToValidate.getSerialNumber());
            
            if (revokedEntry != null) {
                AuditLogger.log("Validación [FALLO CRÍTICO]: El certificado está REVOCADO en la CRL desde: " + revokedEntry.getRevocationDate());
                System.err.println("[ERROR CRÍTICO] El certificado se encuentra en la Lista de Revocación (CRL).");
                return false;
            } else {
                AuditLogger.log("Validación [OK]: El certificado NO está revocado.");
                System.out.println("[VALIDACIÓN] El certificado no está en la lista de revocación.");
            }
        }

        AuditLogger.log("Validación finalizada: CERTIFICADO VÁLIDO Y SEGURO.");
        System.out.println("✅ ESTADO FINAL: CERTIFICADO VÁLIDO Y CONFIABLE");
        return true;
    }
}