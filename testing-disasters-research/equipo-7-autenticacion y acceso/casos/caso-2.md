caso 2:
LinkedIn (2012 – 2016)

En 2012, LinkedIn sufrió un robo masivo de contraseñas.
Inicialmente se creía que eran 6,5 millones de cuentas, pero en 2016 se confirmó que fueron más de 167 millones.

LinkedIn almacenaba las contraseñas con hash SHA-1 sin “sal”.
Esto es una práctica insegura, porque:

SHA-1 ya era un algoritmo débil (rápido de romper).
Al no usar sal (salt), dos usuarios con la misma contraseña tenían el mismo hash.
Los atacantes podían usar tablas de “rainbow” para descifrar millones de contraseñas rápidamente.
