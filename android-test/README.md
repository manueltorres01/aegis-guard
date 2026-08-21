# Aegis Guard Android 1.0.0

Primera versión Android funcional de Aegis Guard. El análisis se realiza localmente sobre la carpeta que el usuario selecciona mediante el selector de documentos de Android. No sube archivos, no elimina datos y no se presenta como sustituto del antivirus del sistema.

## Qué incluye

- Inicio con estado de protección, carpeta seleccionada y métricas del último análisis.
- Análisis local recursivo con límites de 2.000 archivos y 8 niveles de profundidad.
- SHA-256 local para archivos de hasta 8 MiB, sin enviar el contenido a ningún servidor.
- Heurísticas conservadoras: indicadores claros se marcan como maliciosos; ejecutables y modificaciones quedan como sospechosos.
- Resultados con filtros: Todo, Sospechoso, No analizado y Malicioso.
- Exportación del informe completo en JSON desde la propia aplicación.
- Persistencia del último informe en el almacenamiento privado de la app.
- Ajustes de protección y consentimiento de reputación.
- Interfaz oscura basada en Jetpack Compose y Material 3.

## Cómo abrirlo

1. Instala Android Studio reciente, Android SDK 35 y JDK 17.
2. Abre la carpeta `android-test` como proyecto Gradle.
3. Deja que Android Studio sincronice las dependencias.
4. Ejecuta la configuración `app` en un emulador Android 8.0 (API 26) o superior.

El proyecto no incluye el wrapper de Gradle; el workflow de GitHub Actions instala Gradle y genera el APK release sin firma de distribución.

## Descargar el APK desde GitHub

El workflow `Android release APK` compila automáticamente `app-release-unsigned.apk` en Ubuntu cuando cambian estos archivos. En GitHub, abre la ejecución completada de **Actions → Android release APK** y descarga el artefacto `aegis-guard-android-release-unsigned`. Es un APK release sin firma comercial; Android puede pedir confirmación para instalarlo desde fuera de Play Store.

## Siguiente fase

La siguiente iteración debe añadir una firma de distribución, pruebas instrumentadas en dispositivos reales y una capa opcional de reputación. Antes de activar monitorización continua o acciones de aislamiento habrá que validar el modelo de permisos, consumo de batería, recuperación y privacidad.
