caso 1:
Fortinet – CVE-2022-40684:

Esta vulnerabilidad permitía que un atacante no autenticado explotara un canal alternativo o ruta secundaria (“alternate path or channel” — CWE-288) en productos como FortiOS, FortiProxy y FortiSwitchManager.

-Un ataque típico: el atacante envía peticiones HTTP/HTTPS especialmente manipuladas, añade su propia clave SSH al usuario administrador local, luego se conecta por SSH como administrador. 

-Impacto: organizaciones enteras comprometidas; las credenciales o accesos al appliance fueron vendidos en foros de ciberdelincuencia. 

-Aprendizaje: Una interfaz administrativa expuesta externamente + rutas no previstas de autenticación = desastre. Buen para tu login/seguridad: conviene segmentar, limitar acceso a interfaces de gestión y parchear con rapidez.
