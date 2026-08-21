# Aegis Guard Android Test

Prototipo nativo para validar la interfaz y los flujos de Aegis Guard en Android. Esta aplicación **no es todavía un antivirus**: no analiza el almacenamiento real, no elimina archivos, no bloquea procesos y no solicita permisos de red o de archivos.

## Qué incluye

- Inicio con estado de protección y métricas de demostración.
- Análisis rápido simulado con progreso.
- Resultados con filtros: Todo, Sospechoso, No analizado y Malicioso.
- Vista de cuarentena simulada.
- Ajustes de protección y consentimiento de reputación.
- Interfaz oscura basada en Jetpack Compose y Material 3.

## Cómo abrirlo

1. Instala Android Studio reciente, Android SDK 35 y JDK 17.
2. Abre la carpeta `android-test` como proyecto Gradle.
3. Deja que Android Studio sincronice las dependencias.
4. Ejecuta la configuración `app` en un emulador Android 8.0 (API 26) o superior.

El proyecto todavía no incluye el wrapper de Gradle ni un APK generado porque este entorno no tiene Android SDK, `adb` ni Gradle instalados.

## Descargar el APK desde GitHub

El workflow `Android test APK` compila automáticamente `app-debug.apk` en Ubuntu cuando cambian estos archivos. En GitHub, abre la ejecución completada de **Actions → Android test APK** y descarga el artefacto `aegis-guard-android-test-debug`. Es un APK de pruebas sin firma de distribución; Android puede pedir confirmación para instalarlo desde fuera de Play Store.

## Siguiente fase

La siguiente iteración debe añadir permisos Android explícitos, análisis local de archivos y una capa de almacenamiento segura. Antes de activar monitorización o acciones de aislamiento habrá que validar el modelo de permisos, consumo de batería, recuperación y privacidad.
