package revocation;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import audit.AuditLogger;

public class OCSPManager {

    /**
     * Simula un Responder OCSP. Recibe una consulta, verifica el estado y devuelve un objeto OCSPResp firmado.
     */
    public static OCSPResp checkOCSPStatus(
            X509Certificate issuerCert, 
            PrivateKey issuerKey, 
            BigInteger serialToCheck, 
            X509CRL currentCRL) throws Exception {

        AuditLogger.log("Iniciando consulta OCSP para el número de serie: " + serialToCheck);
        
        // Iniciamos el cronómetro para medir la latencia (< 1 segundo)
        long startTime = System.currentTimeMillis();

        // 1. Configuración del motor OCSP y Hash
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();
        BasicOCSPRespBuilder respBuilder = new BasicOCSPRespBuilder(
                new RespID(new JcaX509CertificateHolder(issuerCert).getSubject()));

        // 2. Generar el ID Criptográfico del certificado consultado
        CertificateID certId = new CertificateID(
                digCalcProv.get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCert),
                serialToCheck);

        // 3. Lógica del Responder: Consultar la base de datos (En este caso, nuestra CRL)
        CertificateStatus status = CertificateStatus.GOOD; // Por defecto asumimos que es válido
        
        if (currentCRL != null && currentCRL.getRevokedCertificate(serialToCheck) != null) {
            // Si está en la CRL, cambiamos el estado a REVOCADO
            Date revocationDate = currentCRL.getRevokedCertificate(serialToCheck).getRevocationDate();
            status = new RevokedStatus(revocationDate, org.bouncycastle.asn1.x509.CRLReason.keyCompromise);
        }

        // 4. Ensamblar la respuesta
        respBuilder.addResponse(certId, status);

        // 5. Firmar la respuesta OCSP con la clave de la CA
        org.bouncycastle.operator.ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        OCSPResp response = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, respBuilder.build(signer, null, new Date()));

        // Detenemos el cronómetro
        long latency = System.currentTimeMillis() - startTime;

        // Log de auditoría con latencia
        String statusString = (status == CertificateStatus.GOOD) ? "GOOD" : "REVOKED";
        AuditLogger.log("Respuesta OCSP generada: " + statusString + " (Latencia: " + latency + " ms)");

        return response;
    }

    /**
     * Método auxiliar para imprimir el resultado del objeto OCSPResp en consola.
     */
    public static void printOCSPResponse(OCSPResp response, String targetName) throws Exception {
        BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
        SingleResp[] responses = basicResp.getResponses();
        
        System.out.print("[OCSP LATENCY < 1s] " + targetName + " -> ");
        
        for (SingleResp resp : responses) {
            CertificateStatus status = resp.getCertStatus();
            if (status == CertificateStatus.GOOD) {
                System.out.println("Estado: GOOD (Válido \u2713)");
            } else if (status instanceof RevokedStatus) {
                System.out.println("Estado: REVOKED (Revocado \u2717)");
            } else {
                System.out.println("Estado: UNKNOWN (Desconocido)");
            }
        }
    }
}