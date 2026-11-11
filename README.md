# PAI 4 - DevSecOps y Seguridad en la Cadena de Suministro

Este repositorio contiene la implementacion del pipeline CI/CD con enfoque DevSecOps. El objetivo principal es automatizar el analisis de seguridad sobre una aplicacion web intencionadamente vulnerable OWASP Juice Shop, garantizando que las pruebas se ejecuten en cada cambio de codigo.

---

## Tecnologias y Herramientas Utilizadas

* **Aplicacion Objetivo:** OWASP Juice Shop (Node.js / Angular)
* **Plataforma CI/CD:** GitHub Actions
* **Contenedor:** Docker
* **SAST (Static Application Security Testing):** Semgrep Community Edition
* **SCA (Software Composition Analysis):** npm audit 

---

## Estructura del Pipeline (.github/workflows/ci.yml)

Actualmente, el pipeline cuenta con las etapas iniciales de construccion y analisis estatico configuradas en el entorno:

### 1. Build
* Se descarga el codigo fuente del repositorio (`actions/checkout@v4`).
* Se comprueba que la imagen de Docker de la aplicacion compila correctamente mediante `docker build -t juice-shop-app .`.

### 2. SAST
* Se integra Semgrep Community Edition para escanear el codigo JavaScript y TypeScript 
* **Reglas aplicadas:** Auditoria general de seguridad (`p/security-audit`) y busqueda de credenciales o secretos expuestos (`p/secrets`).
* **Quality Gate:** Configurado en modo aviso (`continue-on-error: true`). Esto permite detectar fallos reales de codigo (como inyecciones o datos sensibles) sin detener la ejecucion del pipeline.

### 3. SCA
* Se ejecuta la inspeccion del archivo `package.json` para comparar las librerias instaladas con bases de datos de vulnerabilidades conocidas (CVEs).
* **Salida de reportes:** Genera archivos de resultados en carpeta `reports/` en formatos JSON (para posterior procesamiento) y TXT.
* **Artefactos:** Los reportes se guardan automaticamente al finalizar la ejecucion mediante `actions/upload-artifact@v4`.
* **Quality Gate:** Configurado en modo aviso (`continue-on-error: true`).
