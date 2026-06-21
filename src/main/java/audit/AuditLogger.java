package audit;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.Date;

public class AuditLogger {

    // Nombre y ruta del archivo CSV que se va a generar
    private static final String FILE_NAME = "audit-report.csv";
    private static final Path FILE_PATH = Paths.get(FILE_NAME);

    public static void log(String message) {
        // 1. Mostrar en consola
        System.out.println("[AUDIT] " + message);

        // 2. Escribir en el archivo CSV usando la API NIO
        try {
            boolean isNewFile = !Files.exists(FILE_PATH);
            StringBuilder sb = new StringBuilder();

            // Si el archivo es nuevo, agregamos los encabezados
            if (isNewFile) {
                sb.append("Fecha_Hora,Nivel,Evento\n");
            }

            // Generar la fecha y hora actual
            String timeStamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

            // Limpiar el mensaje de posibles comas para no romper el formato CSV
            String safeMessage = message.replace(",", ";");

            // Construir la línea CSV (se añade una columna de "Nivel" estática para mayor formalidad)
            sb.append(timeStamp).append(",INFO,").append(safeMessage).append("\n");

            // Escribir la línea en el archivo CSV (CREATE si no existe, APPEND para agregar al final)
            Files.writeString(FILE_PATH, sb.toString(), 
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        } catch (IOException e) {
            System.err.println("Error crítico al intentar escribir en " + FILE_NAME + ": " + e.getMessage());
        }
    }
}