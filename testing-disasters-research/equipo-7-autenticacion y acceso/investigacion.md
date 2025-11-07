              Fallos específicos en sistemas de login y autenticación
  jeferson benjumea - juan jose crespo - muñoz

    Introducción:
Este tema de estudio se evidencia fallos de seguridad en sistemas de login y autenticación, la investigación se hizo con el objetivo de comprender como los errores en el manejo de credenciales,
contraseñas y otros procesos de verificación pueden poner en riesgo nuestra información y pueden permitir el acceso a sistemas críticos que pueden poner en riesgo esa información.
Nos centramos en analizar casos reales de vulnerabilidades que expusieron millones de personas por robos masivos de información,y como algunos fallos podían comprometer completamente la seguridad de una organización
El propósito de esta investigación es identificar las causas técnicas de estos fallos, sus consecuencias y las medidas de mitigación que las empresas adoptaron posteriormente.
Con ello se busca generar conciencia sobre la importancia de aplicar buenas prácticas en el desarrollo seguro de sistemas de autenticación, promoviendo el uso de métodos robustos como el hash seguro, 
la autenticación multifactor (MFA) y el cifrado adecuado de datos sensibles.

En esta investigación se analizan tres casos relevantes de vulnerabilidades y ataques relacionados con la autenticación:

Fortinet – CVE-2022-40684, un caso de bypass de autenticación en sistemas críticos.
LinkedIn (2012–2016), un caso de robo masivo de credenciales por almacenamiento inseguro de contraseñas.
Microsoft – CVE-2025-55241 (Microsoft Entra ID), una falla crítica en tokens de autenticación que permitía acceso no autorizado a cuentas administrativas.
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
Caso      	                Tipo de fallo	Causa raíz	                                                Impacto principal	Medidas                   correctivas
Fortinet CVE-2022-40684	    Bypass de autenticación	Validación incorrecta de rutas administrativas	  Acceso no autorizado a sistemas críticos	  Parches + restricción de interfaz administrativa
LinkedIn (2012–2016)	      Almacenamiento inseguro	Hash débil sin sal (SHA-1)	                      Robo masivo de contraseñas	                Migración a bcrypt + MFA
Microsoft CVE-2025-55241	  Validación de tokens	Uso de tokens antiguos sin verificación completa	  Acceso administrativo remoto	              Parches + auditoría de autenticación
  

