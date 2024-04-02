								
# Tintolmarket

## Descripción

"Tintolmarket" es una solución innovadora en el ámbito del comercio electrónico, específicamente diseñada para la comercialización de vinos. Esta aplicación Java aprovecha las ventajas de una arquitectura cliente-servidor segura, incorporando tecnologías de criptografía y blockchain para garantizar la protección de la comunicación y la integridad de los datos almacenados. Con "Tintolmarket", los usuarios pueden navegar por un catálogo detallado de vinos, realizar transacciones seguras y disfrutar de una experiencia personalizada al visualizar y comprar productos. A pesar de los desafíos enfrentados en la integridad de los datos a través de blockchain, el proyecto se distingue por su compromiso con la seguridad y la creación de una experiencia de usuario excepcional.

## Contenido del Proyecto

El proyecto contiene los siguientes directorios y archivos esenciales para su funcionamiento:

### Directorios

- **KSClients:** Almacena las keystores de los clientes.

### Archivos

- `certServer.cer`: Certificado del servidor.
- `keystore.client`: Keystore para el cliente.
- `truststore.client`: Truststore para el cliente.
- `Tintolmarket.java`: Código fuente del cliente.
- `TintolmarketServer.java`: Código fuente del servidor.

### Estructura de Archivos Generados al Ejecutar

- **BlockChainStore:** Directorio para almacenar los archivos de blockchain.
- **GalleryForServer:** Contiene las imágenes de los vinos añadidos al catálogo.
- `catalogue.txt`: Catálogo de vinos.
- `sellers.txt`: Información de vendedores y productos.
- `users_saldo.txt`: Saldos de los usuarios.
- `params_store.txt`: Parámetros para descifrado.
- `users.cif`: Información cifrada de los usuarios.

## Instrucciones de Instalación

Para ejecutar el programa primero debemos compilar ambos ficheros:
	- javac Tintolmarket.java
	- javac TintolmarketServer.java
	

Una vez compilados primero ejecutamos el servidor 

1.java TintolmarketServer 12345 3432 keystore.server 3432576
2.Ejecutamos los clientes una vez el servidor esta a la espera
	2.1 java Tintolmarket 127.0.0.1 truststore.client Ivet.jks foquita Ivet
	2.2 java Tintolmarket 127.0.0.1 truststore.client Mani.jks 123456 Mani
	2.3 Tantos clientes como quieras (creando las keystores antes)
	
Al ejecutar por primera vez el servidor, se creacran:

-Un directorio BlockChainStore donde se guardaran los archivos block_id.blk
-Un directorio GalleryForServer donde se guardaran las imagenes de los vinos añadidos al catalogo
-Los archivos:
			-catalogue.txt --> id_vino-imagenVino-cantidad-valoracion
			-sellers.txt -->  user_id-idVino-cantidad-precio 
			-users_saldo.txt --> user_id-saldo
			-params_store.txt --> parametros para decifrar
			-users.cif --> userID-certificado
			
Al ejecutar por primera vez un cliente, si nunca antes habia sido ejecutado se crea el directorio
"GalleryForAllClients" que es donde debemos descargar las imagenes de los vinos que vamos a usar.

Tambien si el cliente es nuevo se le crea un directorio especifico con su UserID que en el caso de que el cliente hago un view , contendran la imagen del vino.



###Alvaro Carrillo Quesada---fc59382
###Roberto Arechavala Puertas---fc61272
###Pablo Anel Rancaño---fc61271
