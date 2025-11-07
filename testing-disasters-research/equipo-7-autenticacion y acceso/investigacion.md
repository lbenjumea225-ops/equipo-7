              Fallos específicos en sistemas de login y autenticación
  jeferson benjumea - juan jose crespo - muñoz

    Introducción:
Este tema de estudio se evidencia fallos de seguridad en sistemas de login y autenticación, la investigación se hizo con el objetivo de comprender como los errores en el manejo de credenciales,
contraseñas y otros procesos de verificación pueden poner en riesgo nuestra información y pueden permitir el acceso a sistemas críticos que pueden poner en riesgo esa información.
Nos centramos en analizar casos reales de vulnerabilidades que expusieron millones de personas por robos masivos de información,y como algunos fallos podían comprometer completamente la seguridad de una organización
El propósito de esta investigación es identificar las causas técnicas de estos fallos, sus consecuencias y las medidas de mitigación que las empresas adoptaron posteriormente.
Con ello se busca generar conciencia sobre la importancia de aplicar buenas prácticas en el desarrollo seguro de sistemas de autenticación, promoviendo el uso de métodos robustos como el hash seguro, 
la autenticación multifactor (MFA) y el cifrado adecuado de datos sensibles.


----------------------------------------------
    Timeline: 
    caso-2 ---> caso-1 ----> caso-3
----------------------------------------------


    Caso 1: Fortinet – CVE-2022-40684 (2022)
Descubierta en octubre de 2022, esta vulnerabilidad afectó productos de Fortinet como FortiOS, FortiProxy y FortiSwitchManager, utilizados para administrar redes y cortafuegos en organizaciones de todo el mundo.

    Descripción del fallo:
El error permitía a un atacante remoto bypassear (evadir) la autenticación en la interfaz de administración web, explotando una ruta alterna no autenticada y tambien
podía enviar solicitudes HTTP/HTTPS especialmente diseñadas y ejecutar comandos administrativos sin iniciar sesión.

    Impacto:

-Acceso total al panel de administración sin credenciales.
-Posibilidad de crear nuevos usuarios, cambiar contraseñas o añadir claves SSH.
-Compromiso completo de infraestructuras críticas.
-Confirmado que fue explotado activamente en entornos reales

    Tipo de vulnerabilidad:

Bypass de autenticación y la explotación remota sin credenciales

    Medidas y mitigaciones:

Fortinet lanzó actualizaciones de seguridad el 10 de octubre de 2022 y recomendó restringir el acceso administrativo y actualizar a las versiones corregidas tambien implementar autenticación multifactor (MFA) y segmentar la red para interfaces de gestión.

    caso 2: LinkedIn (2012–2016)
En 2012, LinkedIn sufrió una brecha de seguridad que comprometió inicialmente 6,5 millones de cuentas, aunque en 2016 se reveló que en realidad habían sido 167 millones

    Descripción del fallo:
LinkedIn almacenaba las contraseñas de sus usuarios usando el algoritmo SHA-1 sin sal (salt).
Esto permitió que, una vez robados los hashes, los atacantes pudieran descifrarlos fácilmente mediante ataques de diccionario y fuerza bruta.

    Impacto:

Más de 100 millones de contraseñas descifradas y filtradas en foros clandestinos. Tambien causando la reutilización de credenciales en otros servicios, generando nuevas brechas y
Daños reputacional y pérdida de confianza de los usuarios.

    Tipo de vulnerabilidad

Almacenamiento inseguro de contraseñas con ataques de fuerza bruta y rainbow tables.

    Medidas y mitigaciones

LinkedIn reemplazó SHA-1 por bcrypt con sal única por usuario al igual que implementó MFA opcional y políticas de contraseñas más seguras tambien adoptó monitoreo constante de filtraciones externas.

    Caso 3: Microsoft – CVE-2025-55241 (Microsoft Entra ID)
Descubierta y divulgada en julio de 2025, esta vulnerabilidad afectó al servicio Microsoft Entra ID (antiguo Azure Active Directory), utilizado globalmente para gestionar identidades y accesos en la nube.

    Descripción del fallo

El error permitía a atacantes aprovechar tokens de autenticación inválidos o caducados, emitidos por servicios antiguos de Microsoft, para obtener acceso de administrador global en tenants de Entra ID.
Esto se debía a un fallo en la validación de tokens heredados, lo que dejaba abierta la posibilidad de acceso no autorizado.

    Impacto

-Potencial compromiso de cualquier cuenta administrativa.
-Vulnerabilidad con puntuación CVSS 10.0 (crítica).
-Microsoft confirmó la falla y publicó parches de emergencia en septiembre de 2025.

     Tipo de vulnerabilidad

Falla en la validación de tokens de autenticación y bypass de autorización mediante tokens obsoletos.

    Medidas y mitigaciones

Una ctualización inmediata de Entra ID y deshabilitación de APIs heredadas con una implementación obligatoria de MFA y revisión de claves de servicio y monitoreo continuo de accesos sospechosos.

    Análisis Comparativo
    Caso      	             |    Tipo de fallo	Causa raíz	                                              |   Impacto principal	Medidas                   correctivas
    Fortinet CVE-2022-40684	 |    Bypass de autenticación	Validación incorrecta de rutas administrativas	|   Acceso no autorizado a sistemas críticos	  Parches + restricción de interfaz administrativa
    LinkedIn (2012–2016)	   |    Almacenamiento inseguro	Hash débil sin sal (SHA-1)	                    |   Robo masivo de contraseñas	                Migración a bcrypt + MFA
    Microsoft CVE-2025-55241 |	  Validación de tokens	Uso de tokens antiguos sin verificación completa	|   Acceso administrativo remoto	              Parches + auditoría de autenticación



-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
      "Vulnerabilidades comunes en sistemas de login que se detectan
       con pruebas de seguridad (brute force, session hijacking, etc.)"

Fuerza bruta / credential stuffing
Detección (pruebas): observar intentos repetidos desde la misma IP/usuario, usar herramientas de auditoría para simular múltiples intentos (en entorno de pruebas). Buscar ausencia de rate-limiting o tokens/locks.
Impacto: acceso no autorizado si credenciales débiles o reutilizadas.
Mitigación: bloqueo temporal tras n intentos, rate limiting global y por usuario, CAPTCHA progresivo, detección de patrones de credential stuffing, MFA obligatorio para cuentas sensibles, políticas de contraseña y bloqueo de contraseñas comprometidas.

Enumeración de cuentas (username/email enumeration)
Detección: comparar respuestas (texto, códigos HTTP, tiempos) entre usuario existente y no existente durante login/recuperación.
Impacto: facilita ataques dirigidos y phishing.
Mitigación: respuestas genéricas (p. ej. “credenciales inválidas”), timing equalization, no indicar si el email/usuario existe en flujos públicos.

Inyección SQL / LDAP / No-SQL en formularios de autenticación
Detección: fuzzing y payloads en campos usuario/contraseña; revisión de código para concatenación de consultas.
Impacto: bypass de autenticación, exfiltración de datos.
Mitigación: queries parametrizadas/ORM, sanitizar y validar entradas, least privilege en la cuenta DB.

Almacenamiento inseguro de credenciales (hashing débil / sin salt)
Detección: auditoría de base de datos; comprobar algoritmo de hash si tienes acceso a backups o dump en pruebas autorizadas.
Impacto: recuperación de contraseñas y escalada.
Mitigación: usar Argon2/Bcrypt/PBKDF2 con salt por usuario y parámetros de coste apropiados; policía de rotación/upgrade de hashes.

Sesión: secuestro (session hijacking) y fijación de sesión
Detección: pruebas de manipulación de cookies, observar si se regeneran IDs de sesión tras login, test de logout (si sigue válido). Intentos de reproducir sesión en otra máquina (solo en entorno de pruebas).
Impacto: toma de sesion de usuarios activos.
Mitigación: regenerar ID de sesión tras autenticación, marcar cookies Secure y HttpOnly, SameSite apropiado, implementar expiración inactiva y revocación de sesiones, usar TLS siempre.

Cross-Site Request Forgery (CSRF) en endpoints sensibles (logout, cambiar contraseña)
Detección: probar peticiones desde otro origen sin token CSRF; revisar ausencia de tokens en formularios sensibles.
Impacto: acciones forzadas por usuario autenticado.
Mitigación: tokens CSRF en formularios/requests de estado, SameSite cookies, validación de Origin/Referer si procede.

Cross-Site Scripting (XSS) en mensajes/errores de login
Detección: inyectar payloads en campos que luego se muestran en la UI (p. ej. mensajes de error) y observar reflejo.
Impacto: robo de cookies, ejecución de acciones en contexto del usuario.
Mitigación: escape/encode de salidas, CSP (Content Security Policy), saneamiento en servidor.

Recuperación de contraseña / reset inseguro
Detección: revisar longitud/aleatoriedad de tokens, expiración, posibilidad de reutilización, envío de información sensible en el correo o URL.
Impacto: tomar control de cuentas mediante token predecible o reutilizable.
Mitigación: tokens largos y criptográficamente seguros, expiración corta, single-use, invalidar al usar, confirmar identidad adicional para cuentas críticas, notificación al usuario.

Autorización débil / Escalada de privilegios (horizontal y vertical)
Detección: probar acceso a recursos de otros usuarios cambiando IDs/parametros, intentar endpoints admin con cuenta regular, revisión de controladores de negocio.
Impacto: divulgación o modificación de datos ajenos, acciones administrativas no autorizadas.
Mitigación: checks de autorización en servidor para cada recurso, control de acceso basado en roles (RBAC), pruebas automáticas de control de acceso.

Transporte inseguro y malas configuraciones TLS
Detección: comprobar si el login usa HTTP o TLS obsoleto, analizar cabeceras TLS/HSTS.
Impacto: intercepción de credenciales (MITM).
Mitigación: HTTPS forzado, HSTS, certificados válidos, deshabilitar TLS antiguos, A+ en SSL Labs.

Tokens JWT/Refresh mal gestionados
Detección: revisar caducidad, posibilidad de manipular claims, comprobar revocación.
Impacto: tokens válidos indefinidamente o modificables permiten acceso no autorizado.
Mitigación: firmar y verificar JWTs correctamente, usar expiraciones cortas, refresh tokens seguros almacenados con protección, lista de revocación o rotación.

Exposición de información sensible en mensajes, headers o logs
Detección: revisar respuestas de error, cabeceras y logs accesibles; buscar stack traces.
Impacto: leakage de estructura interna, usuarios, rutas, claves.
Mitigación: mensajes genéricos para usuarios, logging seguro con control de acceso, no registrar contraseñas/secretos.

Open redirect en parámetros de next/redirect
Detección: probar redirecciones a dominios externos a través de parámetros.
Impacto: phishing, bypass de controles.
Mitigación: validar y permitir sólo rutas internas o usar whitelist de dominios.

MFA/2FA mal implementado
Detección: probar reuso de códigos, interceptación en flujo de recuperación, bypass con fallos de lógica.
Impacto: falso sentido de seguridad y acceso no autorizado.
Mitigación: TOTP con secreto protegido, límites de reintento, no enviar códigos sensibles por canales inseguros sin verificación extra.

        Checklist de pruebas rápidas (para ejecutar en un pentest autorizado)

-Intentos de login masivos (ver rate limiting / bloqueo).
-Pruebas de enumeración (comparar respuestas/timing).
-Fuzzing de campos de login/registro (SQL/LDAP/NoSQL/command injections).
-Revisar flujo de “olvidé mi contraseña” y tokens de reset.
-Comprobar regeneración e invalidación de sesiones (logout).
-Revisar cookies (Secure, HttpOnly, SameSite) y cabeceras (HSTS, CSP).
-Probar autorización cambiando parámetros (IDOR).
-Revisar implementación de MFA.
-Verificar TLS/SSL y configuración de cabeceras.
-Revisar logs/responses por divulgación de información.
-Herramientas útiles (para pruebas legítimas / equipos de seguridad)
-Proxies/interceptores: Burp Suite, OWASP ZAP.
-Escaneo y fuzzing: OWASP ZAP, wfuzz, ffuf.
-Análisis de sesiones y cookies: herramientas integradas en proxies.
-Revisión de configuraciones TLS: SSL Labs.


    ¿Qué pruebas específicas debe pasar un sistema de autenticación
     antes de producion
     
    Condiciones previas:
Entorno de preproducción que replica producción (misma configuración TLS, dominios, servicios externos simulados).
Base de datos con datos de prueba (no datos reales).
Variables secretas seguras y diferentes a prod; no exponer credenciales en logs.
CI/CD con pipelines que ejecuten pruebas automatizadas y bloqueen despliegue si fallan.

    Pruebas funcionales:
Registro y verificación de cuenta
Caso: registrar usuario válido → recibir email/OTP → verificar cuenta. Esperado: cuenta creada; token único y expiración.
Login correcto/incorrecto
Caso: credenciales válidas → sesión creada. Credenciales inválidas → mensaje genérico.
Logout
Caso: logout → sesión invalidada y cookie eliminada.
"Olvidé mi contraseña" / reset
Caso: solicitar reset → recibir token (por email) → usar token válido → cambiar contraseña → token no reusable.
Cambio de contraseña autenticado
Caso: usuario cambia contraseña → sesiones previas se invalidan (según política).
Vistas y redirecciones
Caso: login con next/redirect → sólo redirige a rutas permitidas (whitelist).

    Pruebas de seguridad (must-pass — alto prioridad)

Fuerza bruta / rate limiting
Prueba: simular N intentos fallidos (desde misma IP y usuarios distintos). Esperado: bloqueo temporal / backoff / CAPTCHA.
Enumeración de cuentas
Prueba: comparar respuestas para email existente y no existente en login/recuperación. Esperado: respuesta indistinguible y timings equalizados.
Inyección (SQL/NoSQL/LDAP)
Prueba: payloads comunes en usuario/contraseña (p.ej. ' OR '1'='1'). Esperado: ninguna inyección; entrada tratada como dato.
Almacenamiento de contraseñas
Verificación: contraseñas con salt + algoritmo fuerte (Argon2/Bcrypt/SCrypt/PBKDF2). Esperado: hashes no reversibles, parámetros de coste razonables.
Gestión de sesiones
Pruebas: regeneración de session ID tras login, invalida sesión tras logout, expiración por inactividad. Cookies con Secure, HttpOnly, SameSite.
CSRF
Prueba: peticiones desde otro origen sin token CSRF. Esperado: rechazadas.
XSS en formularios/errores
Prueba: inyectar payloads en campos que se muestren en UI. Esperado: salidas escapadas; CSP configurado.
Open redrect
Prueba: manipular redirect con dominio externo. Esperado: rechazado / whitelist.
MFA/2FA
Prueba: enroll/verify TOTP, recovery codes. Esperado: códigos TOTP válidos por tiempo corto, código de recuperación single-use.
Tokens (JWT, reset tokens)
Verificar firma, expiración, revocación/blacklist para refresh tokens.
TLS / transporte
Prueba: todo el tráfico de auth por HTTPS; cabeceras HSTS; TLS moderno (no TLS1.0/1.1).
Pruebas de pentest/IAST/DAST
Ejecutar pentest autorizado y/o ZAP/Burp + reglas SAST en pipeline.

    Pruebas de rendimiento y escalabilidad

Carga de autenticación
Test: simular picos de logins simultáneos (autenticación y creación de sesión). Esperado: latencia aceptable y sin fallos.
Rate-limiter bajo carga
Test: asegurarse que rate-limiting no cause denegación masiva accidental.
Caching y DB
Verificar que sesiones/tokens no sobrecarguen la base de datos; usar mecanismos escalables (Redis para sesiones si aplica).

    Pruebas de resiliencia / confiabilidad

Failover de DB / Cache
Test: simular caída parcial del DB/cache y verificar comportamiento (mensajes, degradación).
Backup y recovery de usuarios
Procedimiento probado para restauración sin pérdida de integridad.
Logging y auditoría
Verificar logs de acceso/auth (sin contraseñas), se registran eventos críticos: login fallido, cambio de contraseña, revocación de tokens.

    Pruebas de usabilidad / UX

Mensajes de error claros pero no reveladores
Prueba: probar varios errores y confirmar mensajes genéricos.
Flujo de recuperación simple y seguro (guías, expiración de token).
Tests de accesibilidad (WCAG básicos) en formularios.

    Pruebas de cumplimiento y privacidad

GDPR/LPD/legislación local
Verificar consentimiento, almacenamiento y eliminación de datos personales, retención de logs.
Revisión de políticas de contraseñas y rotación.

    Pruebas operacionales / monitoreo (must-pass)

Alertas (SIEM / monitoring)
Crear alertas para: aumento inusual de intentos fallidos, patrones de credential stuffing, uso masivo de reset password.
Métricas: latencia auth, tasa de errores, sesiones activas, bloqueos.
Runbooks: pasos claros para incidentes de seguridad (p. ej. compromiso de DB de hashes).

    Pruebas automatizadas recomendadas (CI gate)

Unit tests para lógica de autenticación y validación.
Integration tests: login/logout/reset usando entorno de test.
Contract tests para APIs (OpenAPI/Swagger).
Security scans: SAST en cada PR, DAST en pipeline pre-prod.
Regression tests: verificar que cambios no rompen sesión/MFA.

      Métodos de ataque comunes (y por qué son efectivos)

-Credential stuffing — usar credenciales filtradas en otros sitios; escala masiva con listas de pares leaked; éxito por reutilización de contraseñas. (Akamai/industry reports: miles de millones de intentos en picos históricamente). 
-Brute-force / password spraying — probar contraseñas comunes o listas pequeñas contra muchas cuentas; efectivo contra cuentas con contraseñas débiles y sin rate-limiting. 
-Phishing / Theft / Infostealers — roban credenciales directamente del usuario o del dispositivo (info-stealers recientes generaron grandes dumps). 
-Session hijacking / cookie theft — robo de cookies o tokens (MITM, XSS, exposición en logs) y reuso para suplantar sesión.
-Replay / token manipulation (JWT tampering) — modificar/reenviar tokens si firma/validación mal implementada.
-Explotación de flujos de recuperación de contraseña — tokens predecibles, expiración larga, o flujos que permiten reset sin comprobación suficiente.
-Explotación de autenticación heredada — protocolos legacy (IMAP/POP/SMTP sin MFA) usados como vector para omitir MFA

    Mejores prácticas (hashing, salting, 2FA / MFA y otras)

Hashing & Salting (resumen operativo)

-Algoritmos recomendados: Argon2, bcrypt o scrypt — Argon2 es la elección moderna (ganador del PHC). PBKDF2 sigue siendo aceptable si se configura con alto número de iteraciones. 
-Parámetros/Cost: ajustar work factor / memoria según hardware. Estudios prácticos recomiendan configuraciones de memoria sustanciales (p.ej. parámetros seguros de Argon2 — papers muestran ventajas con ~46 MiB o más según el caso), y elevar iteraciones para PBKDF2 (OWASP sugiere valores altos). 
-Salt: usar salt único por usuario generado con CSPRNG; almacenar salt en la BD junto al hash (no hace falta cifrar el salt). Evitar reuso de salt. 
-Pepper (opcional): valor secreto adicional almacenado fuera de la BD (p. ej. en Vault) para añadir defensa en profundidad.
-Migración: si migras hashes viejos (MD5/SHA1), rehashea en el próximo login o forzar reset masivo.
-No almacenar contraseñas en texto claro ni en logs.

    2FA / MFA

-Efectividad: MFA reduce enormemente la probabilidad de compromiso; Microsoft y SANS han reportado que MFA puede bloquear >99% de los ataques automáticos cuando se implementa correctamente — especialmente si es phishing-resistente (FIDO2 / hardware keys / passkeys). No obstante, factores de segundo paso débiles (SMS, llamadas) pueden ser socialmente burlados. 
-Recomendación: preferir FIDO2 / WebAuthn / hardware keys o TOTP con protección de registro y backup codes bien gestionados; usar mecanismos para detectar y bloquear técnicas de MFA-bypass (phishing AitM, push fatigue).
-Política: MFA obligatorio para cuentas con privilegios; permitir onboarding gradual y métodos de recuperación seguros (códigos de recuperación single-use y procesos de verificación manual).

    Pruebas de autenticación y autorización — lista detallada para investigación

    Pruebas de autenticación (login / gestión de credenciales)
-Fuerza bruta / password spraying
Objetivo: comprobar rate-limiting y bloqueo por intentos.
Herramienta: Hydra / Burp Intruder / scripts controlados.
Criterio: tras N intentos (definir N = 5–10) desde la misma cuenta o IP debe aplicarse bloqueo, captcha o backoff.
-Credential stuffing (simulación)
Objetivo: medir exposiciones por credenciales filtradas.
Herramienta: herramientas simuladoras de stuffing en entorno de pruebas (o AuthREST para APIs).
Criterio: detección/mitigación automática (rate-limit, challenge) y bloqueo de cuentas con patrones anómalos. 
-Pruebas de recuperación de contraseña
Objetivo: verificar tokens (aleatoriedad, expiración, single-use).
Test: solicitar reset, interceptar token, reusar token.
Criterio: token único, expiración corta (p. ej. <1 h), token no reutilizable.
-Análisis de almacenamiento de credenciales
Objetivo: verificar hashing, salt y parámetros.
Método: revisión de configuración, audit logs; si es posible en entorno seguro, realizar cracking controlado para estimar resistencia.
Criterio: Algoritmo seguro (Argon2/bcrypt/scrypt/PBKDF2 con parámetros altos), salt único por cuenta.
-MFA enrolamiento y bypass
Objetivo: probar enroll, login con MFA, recuperación con recovery codes y resistencia a push-fatigue/OTP reuse.
Criterio: códigos TOTP sólo válidos por periodo corto; recovery codes single-use; detectar múltiples reintentos y bloquear.
-TLS / transporte
Objetivo: asegurar que todas las rutas de autenticación usan HTTPS y TLS moderno.
Herramienta: SSL Labs / testssl.sh.
Criterio: A+ o al menos ausencia de TLS <1.2 y cifrados inseguros.

    Pruebas de sesión y secuestro

-Session fixation & regeneration
Test: fijar session id antes de login y verificar si el server regenera id tras autenticación.
Criterio: ID regenerado; anterior inválido.

-Cookie flags & theft
Test: revisar HttpOnly, Secure, SameSite y probar si la cookie puede ser leída por JS (XSS).
Criterio: HttpOnly + Secure en cookies de sesión.

-Replay / token reuse
Test: capturar token y reusar desde otra IP.
Criterio: detección de reuse y bloqueo/invalidación o binding de token (device IP/user agent) según política.

    Pruebas de autorización (control de acceso)

-IDOR / Horizontal Privilege Escalation
Test: intentar acceder a recursos con otros IDs (cambiar /user/123 → /user/124).
Criterio: acceso denegado si no corresponde al rol/propietario.

-Vertical Privilege Escalation
Test: acciones admin con cuenta normal (probar endpoints admin con token regular).
Criterio: 403/401 y logs de intento.

-API token scope & claims
Test: modificar JWT claims (role, uid) y reenviarlo.
Criterio: firma verificada, claims server-side autoritarios (el servidor no confía en claims del cliente sin comprobación).

    Pruebas de resiliencia y detección

-Simular picos de autenticación (stress tests) para ver que rate-limiter y servicios no se degradan.
-Simular ataques combinados: stuffing + IP rotation + user agent spoofing para verificar detección bot/anti-abuse.
-Pentest / DAST / SAST: ejecutar Burp/ZAP + SAST (Semgrep, SonarQube) e incluir pruebas manuales de flujo lógico.

    Métricas y criterios científicos que puedes usar en la investigación

-Tasa de cuentas comprometidas = (nº de cuentas con credenciales en leaks relacionadas / total de cuentas) × 100. (Fuente: HIBP, feeds OSINT). 
Wikipedia
-Tasa de éxito de credential stuffing (simulada) = accesos válidos / intentos totales. (para estimar riesgo económico). 
Comparitech
-Tiempo medio hasta detección (MTTD) y remediación (MTTR) tras un intento de takeover.
-% de cuentas con MFA habilitado y % con password reuse detectado.
-Coste de cracking por cuenta (modelo económico: coste computacional para romper hashes con parámetros actuales — relevante cuando comparas algoritmos, ver estudio Argon2)

Recursos / lecturas recomendadas (rápidas)

-Have I Been Pwned — monitorización de credenciales filtradas. 
Wikipedia
-Microsoft Security blog — impacto y recomendación de MFA (MFA bloquea >99% ataques automatizados cuando se usa correctamente). 
Microsoft
-Artículos sobre credential stuffing / medidas defensivas (ej. análisis de Akamai/industry blogs). 
Comparitech
-Investigaciones académicas sobre Argon2 y parámetros seguros. 
arXiv
-OWASP Cheat Sheets (Authentication, Session Management, Password Storage) — guías prácticas para pruebas y configuración (recomiendo consultarlas directamente para checklists y ejemplos).
    
    reflexion personal
Durante el desarrollo de esta investigación sobre fallos en sistemas de login y autenticación, me di cuenta de la enorme responsabilidad que implica diseñar e implementar mecanismos de seguridad en cualquier sistema informático. Al principio pensaba que los ataques a plataformas grandes como LinkedIn o Microsoft eran situaciones lejanas, pero al analizar cada caso comprendí que muchos de esos errores pudieron haberse evitado con prácticas básicas de protección de contraseñas y control de accesos.
El caso de Fortinet me llamó especialmente la atención, porque muestra cómo un simple descuido en la validación de rutas administrativas puede abrir la puerta a atacantes con acceso total. En el caso de LinkedIn, me impactó saber que millones de contraseñas se filtraron solo por usar un algoritmo inseguro. Y el caso de Microsoft demuestra que incluso las empresas más grandes pueden tener vulnerabilidades si no actualizan sus sistemas de autenticación de manera constante.
Esta investigación me ayudó a entender que la seguridad no depende solo de las herramientas, sino también de la forma en que se aplican y mantienen. Aprendí que siempre se deben realizar pruebas antes de lanzar un sistema, usar técnicas modernas de cifrado y reforzar la autenticación con métodos adicionales como el MFA. En conclusión, este trabajo me hizo más consciente de la importancia de desarrollar software seguro y de asumir la seguridad como una parte esencial del proceso, no como un paso final.








