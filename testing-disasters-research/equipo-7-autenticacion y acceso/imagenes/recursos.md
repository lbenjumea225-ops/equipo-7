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

# Análisis Comparativo

### 📋 Tabla Comparativa
| Métrica | Fortinet | LinkedIn | Microsoft |
|:--|:--:|:--:|:--:|
| Cuentas comprometidas | 12,000 | 167,000,000 | <1,000 (confirmadas) |
| Tipo de ataque | Bypass de autenticación | Fuerza bruta / hash débil | Bypass de tokens |
| Severidad | Crítica | Alta | Crítica |
| Año | 2022 | 2012–2016 | 2025 |

### 🧩 Patrones Comunes

| N.º | Patrón Común / Problema Raíz | Descripción |
|:--:|:--|:--|
| 1 | Reutilización de credenciales | Uso de contraseñas débiles o repetidas. |
| 2 | Falta de mecanismos anti-bot | Permite fuerza bruta sin límites. |
| 3 | Detección lenta de intrusiones | No se generan alertas ante accesos anómalos. |
| 4 | Sesiones inseguras | Tokens sin renovación ni flags seguros. |
| 5 | Almacenamiento débil | Uso de SHA-1 o MD5 sin sal. |

---
# Patrones Comunes y Tipos de Pruebas
### 🧪 Tipos de Pruebas Recomendadas

| N.º | Tipo de Prueba | Objetivo |
|:--:|:--|:--|
| 1 | Simulación de fuerza bruta | Verificar bloqueos y límites de login. |
| 2 | Auditoría de almacenamiento | Revisar uso de hash y sal por usuario. |
| 3 | Testing de sesión | Evaluar expiración, fijación y regeneración de ID. |
| 4 | Validación de MFA | Comprobar resistencia a bypass. |
| 5 | Revisión de logs | Buscar exposición de datos o tokens. |

# Conclusiones y Lecciones Aprendidas

Las vulnerabilidades en autenticación pueden comprometer infraestructuras completas.  
- Los ataques más comunes derivan de errores de configuración y almacenamiento débil.  
- Las buenas prácticas como **hashing seguro, MFA obligatorio y auditorías periódicas** reducen significativamente el riesgo.  
- La detección temprana y el monitoreo continuo son esenciales para mitigar el impacto.

# Referencias
windsor, C. (2022, Octubre 14). [Update Regarding CVE-2022-40684]. . https://www.fortinet.com/blog/psirt-blogs/update-regarding-cve-2022-40684
http://packetstormsecurity.com/files/169431/Fortinet-FortiOS-FortiProxy-FortiSwitchManager-Authentication-Bypass.html 
http://packetstormsecurity.com/files/171515/Fortinet-7.2.1-Authentication-Bypass.html 
https://fortiguard.com/psirt/FG-IR-22-377 
http://packetstormsecurity.com/files/169431/Fortinet-FortiOS-FortiProxy-FortiSwitchManager-Authentication-Bypass.html 
http://packetstormsecurity.com/files/171515/Fortinet-7.2.1-Authentication-Bypass.html 
https://fortiguard.com/psirt/FG-IR-22-377 
https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2022-40684 
[Sin autor] (2022, Octubre 18). Vulnerabilidad en Fortinet FortiOS, FortiProxy y FortiSwitchManager (CVE-2022-40684). incibe-cert. https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2022-40684

[Sin autor] (2025, Enero 16). Se filtraron los archivos de configuración de 15.000 firewalls de Fortinet. linked in. https://es.linkedin.com/pulse/se-filtraron-los-archivos-de-configuraci%C3%B3n-15000-firewalls-fortinet-iihsc
[Sin autor] (2022, Octubre 27). Fortinet Authentication Bypass Vulnerability Analysis – CYFIRMA. cyfirma. https://www.cyfirma.com/research/fortinet-authentication-bypass-vulnerability-exploited-by-threat-actors/
[Sin autor] (2025, Junio 19). Filtración de datos récord de 16 mil millones de la que nadie había oído hablar.. linked in. https://es.linkedin.com/pulse/filtraci%C3%B3n-de-datos-r%C3%A9cord-16-mil-millones-la-que-nadie-hab%C3%ADa-2zvcc
[Sin autor] (2025, Junio 20). La filtración de 16.000 millones de contraseñas sería la más grande de la historia. Si no fuera porque es un gigantesco refrito. xataka. https://www.xataka.com/seguridad/filtracion-16-000-millones-contrasenas-seria-grande-historia-no-fuera-porque-gigantesco-refrito
[Sin autor] (2025, Septiembre 4). Azure Entra ID Elevation of Privilege Vulnerability. microdoft. https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-55241

[Sin autor] (2025, Octubre 14). Death by Token: Understanding CVE-2025-55241. practical 365. https://practical365.com/death-by-token-understanding-cve-2025-55241/
