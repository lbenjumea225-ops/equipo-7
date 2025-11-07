caso 3: Microsoft – CVE-2025-55241 (Microsoft Entra ID)

Un fallo crítico en Microsoft Entra ID permitía que atacantes usaran tokens inválidos (“actor tokens”) emitidos por un servicio legado (ACS → Azure AD Graph API)
para obtener acceso de administrador global en casi cualquier tenant, sin que la víctima lo supiera. 
Severidad máxima (CVSS 10/10). Microsoft lo reconoció a mediados de julio de 2025 y parcheó el 4 de septiembre. 
Los servicios “legados” o “deprecated” pueden convertirse en punto débil. En tu sistema de login/roles: ten cuidado con componentes de autenticación que quedan fuera de las rutas “normales” o que permiten bypass.

