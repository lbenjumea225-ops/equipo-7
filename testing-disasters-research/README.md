
# Equipo 7 — Fallos en Sistemas de Login y Autenticación

##  Tabla de Contenidos
1. [Introducción](#introducción)  
2. [Casos Investigados](#casos-investigados)  
   - [Caso 1: Fortinet – CVE-2022-40684](#caso-1-fortinet--cve-2022-40684)  
   - [Caso 2: LinkedIn (2012–2016)](#caso-2-linkedin-2012–2016)  
   - [Caso 3: Microsoft – CVE-2025-55241 (Microsoft Entra ID)](#caso-3-microsoft--cve-2025-55241-microsoft-entra-id)  
3. [Análisis Comparativo](#análisis-comparativo)  
4. [Vulnerabilidades Comunes](#vulnerabilidades-comunes)  
5. [Pruebas de Autenticación y Autorización](#pruebas-de-autenticación-y-autorización)  
6. [Conclusiones y Buenas Prácticas](#conclusiones-y-buenas-prácticas)  
7. [Referencias](#referencias)  
8. [Enlace a la Página Web](#enlace-a-la-página-web)

---

## Introducción
Esta investigación analiza *fallos críticos en sistemas de login y autenticación*, con el fin de comprender cómo los errores en la validación de credenciales y el almacenamiento inseguro de contraseñas han permitido accesos no autorizados a millones de cuentas.  

Se estudiaron tres casos representativos:  
- *Fortinet – CVE-2022-40684*, bypass de autenticación en sistemas críticos.  
- *LinkedIn (2012–2016)*, robo masivo de credenciales por almacenamiento inseguro.  
- *Microsoft – CVE-2025-55241*, falla en la validación de tokens en Entra ID.  

El propósito es identificar las causas, consecuencias y medidas adoptadas, promoviendo el uso de *hash seguro, salting, MFA* y pruebas de seguridad antes de la puesta en producción.

---

##  Casos Investigados

### 🧱 Caso 1: Fortinet – CVE-2022-40684
*Año:* 2022  
*Tipo de fallo:* Bypass de autenticación en interfaces administrativas.  
*Descripción:* Permitía a atacantes enviar peticiones HTTP/HTTPS manipuladas y acceder sin credenciales a productos Fortinet (FortiOS, FortiProxy, FortiSwitchManager).  
*Impacto:* Acceso total a paneles de administración, creación de usuarios no autorizados y control del sistema.  
*Mitigación:* Actualización de firmware, restricción de acceso administrativo y activación de MFA.

---

### 🧱 Caso 2: LinkedIn (2012–2016)
*Año:* 2012–2016  
*Tipo de fallo:* Almacenamiento inseguro de contraseñas.  
*Descripción:* LinkedIn almacenaba contraseñas usando SHA-1 sin sal, lo que permitió descifrarlas con ataques de fuerza bruta.  
*Impacto:* Más de 167 millones de credenciales comprometidas y reutilización en otros servicios.  
*Mitigación:* Migración a bcrypt con sal, implementación de MFA y políticas de seguridad mejoradas.

---

### 🧱 Caso 3: Microsoft – CVE-2025-55241 (Microsoft Entra ID)
*Año:* 2025  
*Tipo de fallo:* Validación deficiente de tokens de autenticación.  
*Descripción:* Permitir el uso de tokens heredados e inválidos para obtener acceso de administrador global.  
*Impacto:* Riesgo de compromiso de cuentas de alto privilegio en entornos corporativos.  
*Mitigación:* Parches de emergencia, auditoría de tokens, MFA obligatorio y deshabilitación de APIs obsoletas.

---

## Análisis Comparativo

| *Caso* | *Año* | *Tipo de fallo* | *Causa raíz* | *Métodos de ataque* | *Credenciales comprometidas (cantidad)* | *Impacto principal* | *Medidas correctivas* |
|-----------|----------|------------------|----------------|------------------------|-------------------------------------------|------------------------|--------------------------|
| *Fortinet – CVE-2022-40684* | 2022 | Bypass de autenticación | Validación incorrecta de rutas y controles administrativos | Peticiones HTTP manipuladas | N/A | Acceso total a panel administrativo | Parches + MFA + restricción de acceso |
| *LinkedIn (2012–2016)* | 2012–2016 | Almacenamiento inseguro de contraseñas | Uso de SHA-1 sin sal | Fuerza bruta / rainbow tables | 167 millones | Exposición masiva de credenciales | bcrypt + MFA + políticas seguras |
| *Microsoft – CVE-2025-55241* | 2025 | Validación de tokens insegura | Uso de tokens heredados sin verificación | Reutilización de tokens inválidos | No reportado | Acceso a cuentas administrativas | Parches + auditoría + MFA |

---

##  Vulnerabilidades Comunes
- Uso de algoritmos de *hash débiles* (MD5, SHA-1).  
- Ausencia de *sal y pepper* en contraseñas.  
- *Sesiones mal gestionadas* o tokens sin expiración.  
- *Interfaces administrativas expuestas* al público.  
- Falta de *autenticación multifactor (MFA)*.  

---

## 🧪 Pruebas de Autenticación y Autorización
Antes del despliegue, un sistema de autenticación debe aprobar:
1. *Prueba de fuerza bruta:* bloqueo tras intentos fallidos.  
2. *Session Hijacking:* caducidad y validación de sesión.  
3. *SQL/LDAP Injection:* sanitización de entradas.  
4. *Password Storage:* verificación de hash seguro y sal.  
5. *MFA Testing:* comprobación del segundo factor.  
6. *Privilege Escalation:* separación efectiva de roles.  

---

##  Conclusiones y Buenas Prácticas
Los fallos estudiados demuestran que la seguridad no depende solo del usuario, sino de la *implementación técnica del sistema*.  
Las mejores prácticas incluyen:
- Hashing con *bcrypt, scrypt o Argon2*.  
- Aplicar *sal y pepper* únicas por usuario.  
- Exigir *MFA* en accesos administrativos.  
- Monitorear intentos de login y eventos sospechosos.  
- Auditar y actualizar sistemas de autenticación periódicamente.

---

##  Referencias
- Fortinet PSIRT Advisory – CVE-2022-40684.  
- TechRadar (2025). Microsoft Entra ID critical authentication flaw (CVE-2025-55241).  
- Wired (2016). LinkedIn breach exposes 117 million credentials.  
- OWASP Foundation. Authentication and Session Management Cheat Sheet.  
- CISA. Authentication Bypass and Credential Security Guidelines.
---
