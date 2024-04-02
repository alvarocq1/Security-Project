									#Proyecto 1 Fase 2


###Alvaro Carrillo Quesada---fc59382
###Roberto Arechavala Puertas---fc61272
###Pablo Anel Rancaño---fc61271

"Tintolmarket" es una aplicación Java avanzada de comercio electrónico diseñada para la gestión y venta de vinos, implementando una arquitectura cliente-servidor segura. Utiliza criptografía y tecnología blockchain para asegurar la comunicación y la integridad de los datos, respectivamente. Los usuarios pueden explorar un catálogo de vinos detallado, realizar compras, y visualizar imágenes de productos, todo dentro de un entorno seguro. A pesar de enfrentar desafíos en la integridad de los datos almacenados en blockchain, el proyecto destaca por su enfoque en la seguridad y una experiencia de usuario personalizada. "Tintolmarket" representa un esfuerzo tecnológico notable en el ámbito del comercio electrónico especializado.


En el zip , tenemos desde un inicio los siguientes archivos y directorios:

Directorio KSClients --> guarda las keystores de los clientes

Archivos:
		-certServer.cer
		-keystore.client
		-truststore.client
		-Tintolmarket.java
		-TintolmarketServer.java


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

No hemos conseguido hacer el mantenimiento de la integridad tanto de los blockchains como de los archivos.Lo dejamos comentado en el codigo, siempre nos sale hash invalido.



