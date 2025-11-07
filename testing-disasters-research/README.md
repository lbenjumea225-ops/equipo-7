# Fallos específicos en sistemas de login y autenticación

**Autor:** jeferson benjumea morales / juan jose crespo / juan andres londoño

**Materia / Proyecto:**  Sistemas de Autenticación y Control de Acceso

**Fecha:** Noviembre 2025  

Repositorio con la documentación técnica y la página web del proyecto sobre vulnerabilidades en autenticación y casos reales.

# Descripción General del Proyecto

Este proyecto presenta un análisis comparativo de tres vulnerabilidades reales relacionadas con sistemas de autenticación:

1. **Fortinet – CVE-2022-40684 (2022)**  
2. **LinkedIn – Brecha de contraseñas (2012–2016)**  
3. **Microsoft – CVE-2025-55241 (Microsoft Entra ID)**  

El propósito es identificar patrones comunes, tipos de ataques, medidas de mitigación y buenas prácticas en autenticación segura.

# Objetivos
- Comprender las vulnerabilidades más comunes en sistemas de login.  
- Analizar los impactos técnicos y organizacionales de cada caso.  
- Evaluar las medidas preventivas implementadas.  
- Proponer buenas prácticas y estrategias de seguridad.

# Casos de Estudio

### 🔐 Caso 1: Fortinet – CVE-2022-40684 (2022)
- **Descripción:** Fallo que permitía bypassear la autenticación en la interfaz web administrativa.  
- **Impacto:** Acceso total al panel, creación de usuarios, compromiso de infraestructuras críticas.  
- **Tipo:** Bypass de autenticación y ejecución remota sin credenciales.  
- **Mitigaciones:** Actualización inmediata, MFA, restricción de acceso y segmentación de red.

---

### 🔑 Caso 2: LinkedIn (2012–2016)
- **Descripción:** Contraseñas almacenadas con SHA-1 sin sal, permitiendo ataques de fuerza bruta y diccionario.  
- **Impacto:** Más de 100 millones de contraseñas descifradas y reutilización en otros servicios.  
- **Tipo:** Almacenamiento inseguro de contraseñas.  
- **Mitigaciones:** Migración a bcrypt con sal única, MFA opcional y monitoreo continuo de filtraciones.

---

### 🧭 Caso 3: Microsoft – CVE-2025-55241 (Microsoft Entra ID)
- **Descripción:** Falla en la validación de tokens caducados que permitía acceso administrativo.  
- **Impacto:** Compromiso potencial de cuentas globales, CVSS 10.0 (crítica).  
- **Tipo:** Bypass de autorización mediante tokens obsoletos.  
- **Mitigaciones:** Parche de seguridad, deshabilitar APIs antiguas, MFA obligatorio y rotación de claves.
