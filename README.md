# Laboratorio de PKI Jerárquica - Criptografía Aplicada en Ciberseguridad

## Descripción
Implementación automatizada de una Infraestructura de Clave Pública (PKI) jerárquica en Java. Este proyecto simula el ciclo de vida completo de certificados digitales X.509 v3, incluyendo la generación de una Autoridad Raíz (Root CA) *offline*, una Autoridad Subordinada (Sub CA), emisión de certificados para entidades finales, y un motor de revocación estructurado (CRL).

## Requisitos Previos
* Java Development Kit (JDK) 11 o superior.
* Apache Maven 3.x.
* Entorno de ejecución: Windows (PowerShell) o Linux (Bash).

## Secuencia de Despliegue Automatizado
El laboratorio cuenta con un script de automatización que limpia entornos previos, compila el código fuente y ejecuta el orquestador principal.

1. Abrir una terminal de PowerShell como administrador (o con permisos de ejecución).
2. Posicionarse en el directorio raíz del proyecto: `cd C:\Ruta\Hacia\PKI`
3. Ejecutar el script: `.\deploy_pki.ps1`

## Fases del Orquestador (Main.java)
El orquestador automatiza los siguientes procesos técnicos:
1. **Generación Root CA:** Creación de claves RSA 4096-bit e inyección de extensiones `BasicConstraints` y `KeyUsage`.
2. **Generación Sub CA:** Firma delegada, establecimiento de cadena de confianza (`ca-chain.pem`) y aislamiento perimetral simulado.
3. **Emisión de Entidades Finales:** Creación de certificados TLS para usuarios y servidores locales (`localhost`), empaquetados en contenedores seguros PKCS#12 (`.p12`).
4. **Motor de Revocación:** Generación de la Lista de Revocación de Certificados (CRL) con un parámetro estricto de `Next Update` $\le 24$ horas para respuesta rápida a incidentes.
5. **Auditoría Técnica:** Exportación continua de eventos al archivo `audit-report.csv`, ideal para su futura ingesta y monitorización en plataformas SIEM como Wazuh.

## Estructura de Artefactos Generados
Todos los artefactos criptográficos se alojan de forma segura en el directorio `/certificates`:
* `root-ca.key` / `root-ca.crt`: Núcleo de la confianza.
* `sub-ca.key` / `sub-ca.crt`: Autoridad delegada operativa.
* `ca-chain.pem`: Cadena de confianza completa para validación de clientes.
* `sub-ca.crl`: Lista negra de números de serie comprometidos.