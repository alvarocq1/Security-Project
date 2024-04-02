


import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;



public class Tintolmarket {
    
    private String IP = ""; //IP del host (la de nuestro PC en este caso)
    private String Port = ""; //Puerto del servidor
    private String password = "";
    private String userID = "";
    private String keystore_name = "";
    private String truststore_name = "";
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private KeyStore keystore;
    private String clients_folder = "";
    private String client_folder = "";

    
    public static void main(String[] args) throws Exception {
        Tintolmarket client = new Tintolmarket(args[0],args[1],args[2],args[3],args[4]);
        client.startMarkket();
    }

    public Tintolmarket(String adress , String truststore , String keystore_name , String pswd , String userID) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, UnrecoverableKeyException{
       
        if(adress.indexOf(":") != -1){
            String [] aux = adress.split(":");
            IP = aux[0];
            Port = aux[1];
        }
        else{
            IP = adress;
            Port = "12345";
        }

        this.keystore_name = keystore_name;
        this.password = pswd;
        this.userID = userID;
        this.truststore_name = truststore;

        String ruta = "./KSClients/" + keystore_name;
        FileInputStream kfile = new FileInputStream(ruta); //keystore
        keystore = KeyStore.getInstance("PKCS12");
        keystore.load(kfile, password.toCharArray());
        privateKey = (PrivateKey)keystore.getKey(userID, password.toCharArray());
    }

    public byte[] sign(long nonce) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException{
        Signature s = Signature.getInstance("MD5withRSA");
        s.initSign(privateKey);
        byte[] buf = new byte[8];
        for (int i = 0; i < 8; i++) {
            buf[i] = (byte)(nonce >> (i * 8));
        }
        s.update(buf);

        return s.sign();
        
    }
    public void startMarkket() throws NumberFormatException, UnknownHostException, IOException, ClassNotFoundException, NoSuchAlgorithmException, CertificateException, KeyStoreException, InvalidKeyException, SignatureException{

        //Creacion de la truststore para el cliente

        /*
         *Exportar el certificado autoasignado del servidor
         *keytool -exportcert -alias server -file certServer.cer -keystore keystore.server
         *Importarlo en la truststore
         *keytool -importcert -alias trust -file certServer.cer -keystore truststore.client
         */
        //Definimos las propiedades antes de la creacion del SSLSocket
        System.setProperty("javax.net.ssl.trustStore", truststore_name);
        System.setProperty("javax.net.ssl.trustStorePassword", "3432576");
        
        SocketFactory sf = SSLSocketFactory.getDefault( );
        SSLSocket s = (SSLSocket) sf.createSocket(IP, Integer.parseInt(Port));
        
        
        try{
          
            ObjectOutputStream outStream = new ObjectOutputStream(s.getOutputStream());
           
            ObjectInputStream inStream = new ObjectInputStream(s.getInputStream());
        
            outStream.writeObject(userID);
            
            long nonce = (long)inStream.readObject();
            boolean flag = (boolean)inStream.readObject();

            byte[] sign = sign(nonce);

            outStream.writeObject(sign);
            
            if(!flag){ //No esta registardo           
                outStream.writeObject(nonce);
                outStream.writeObject(keystore.getCertificate(userID));            
            }


        

        File dir_actual = new File("");
        clients_folder = dir_actual.getAbsolutePath()  + "/GalleryForAllClients/";

        File directorio = new File(clients_folder );
        if (!directorio.exists()) {
            if (directorio.mkdirs())
                System.out.println("Directorio GalleryForAllClients creado");	
           }
        
        //log = (boolean)inStream.readObject();

                if(true){
                    client_folder = dir_actual.getAbsolutePath()  + "/" + this.userID + "/";
                    
                    File dir = new File(client_folder );
                    if (!dir.exists()) {
                        if (dir.mkdirs())
                            System.out.println("Directorio especifico para el cliente creado\n\n");	
                        }
                    System.out.println("Login Correcto");
                    System.out.println("\nMenu\n" + "Available Options:\n\n" + "add<wine><image>\n" +
                    "sell<wine><value><quantity>\n" + "view<wine>\n" + "buy<wine><seller><quantity>\n" + 
                    "wallet\n" + "classify<wine><stars>\n" + "talk<user><message>\n" + "read\n" + "list\n\n");
                }
                else{
                    System.out.println("Login Incorrecto");
                    System.exit(-1);
                }

                Scanner OpcionMenu = new Scanner (System.in);
                
                String consola = OpcionMenu.nextLine();
                
                outStream.writeObject(consola);
                boolean estado = (boolean)inStream.readObject();
                
                while(estado){
                    
                    

                    String [] consol_split = consola.split(" ");
                    System.out.println("Opcion -" + consol_split[0] + " seleccionada" );
                      switch(consol_split[0]){
                        
                        case "add": case "a":

                            
                            /*Para enviar la imagen 
                            Abrimos el archivo que desemos enviar y usamos el 
                            flujo de salida OutStream que ya tenemos
                            Las imagenes por el lado del cliente estarn guardadas 
                            en una carpeta llamada "GaleryForClient" */
                            boolean aux_ = (boolean)inStream.readObject();
                            if(aux_){
                                BufferedInputStream bis;
                                BufferedOutputStream bos;
                                File imagen = new File(clients_folder + consol_split[2]);
                                

                                bis = new BufferedInputStream(new FileInputStream(imagen));
                                bos = new BufferedOutputStream(s.getOutputStream());
                                
                                byte [] fileData =  bis.readAllBytes();
                                outStream.writeObject(fileData.length);
                                
                                // Enviamos los datos del archivo al servidor
                                bos.write(fileData);
                                bos.flush(); // Aseguramos que se envíe todo lo que hay en el buffer


                                //bos.close();
                                //bis.close();
                                System.out.println("Vino correctamente añadido al catalogo");
                            }
                            else{
                                System.out.println("ERROR: Vino ya existente");
                            }
                            
                               
                        break;
                        case "sell": case "s":
                            boolean sell = (boolean)inStream.readObject();
                            
                            if(!sell){
                                System.out.println("El vino no esta registrado en el catalogo");
                            }
                            else{
                                System.out.println("El vino  esta registrado en el catalogo");
                                String transaction = (String)inStream.readObject();
                                System.out.println("Esta es la transaccion que va a realizar: \n" + transaction +
                                " \ndesea continuar y firmar la operacion? si/no-->");
                               
                    
                                String respuesta = OpcionMenu.nextLine();
                                
                                String ConsolUpper = respuesta.toUpperCase();
                                if(ConsolUpper.equals("SI")){
                                    //Mando la transaccion firmada
                                    Signature signature = Signature.getInstance("MD5withRSA");
                                    signature.initSign(privateKey);
                                    byte[] buf = transaction.getBytes();
                                    
                                    signature.update(buf);
                                    outStream.writeObject(true);
                                    outStream.writeObject(signature.sign());
                                    boolean aux = (boolean)inStream.readObject();
                                    if(aux)
                                        System.out.println("Vino puesto a la venta correctamente");
                                    else
                                        System.out.println("Error al verificar la firma , no se pudo realizar la operacion");
                                }
                                else{
                                    outStream.writeObject(false);
                                    System.out.println("...Operacion cancelada...");
                                }
                            }
                             
                        break;
                        case "view": case "v":
                            boolean view = (boolean)inStream.readObject();
                            if(view){ //Si el vino existe el cliente se prepara para la recepcion de l aimagen del vino
                                BufferedInputStream bis = new BufferedInputStream(s.getInputStream());
                                //Recibo del servidor el nombre de la imagen
                                String file_name = (String)inStream.readObject();
                                File imagen = new File(client_folder + file_name );
                                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(imagen));


                                int size = (Integer)inStream.readObject();
                                byte [] buffer = new byte[size];
                                int bytesLeidos = bis.read(buffer);
                                

                                //Escribimos los datos recibidos en el objeto File

                                
                                bos.write(buffer, 0, bytesLeidos);

                                bos.close();

                            }
                            System.out.println((String)inStream.readObject());

                        break;
                        case "buy": case "b":
                            String transaction; 
                            System.out.println((String)inStream.readObject());
                            
                            boolean seguir = (boolean)inStream.readObject();
                            if(seguir){
                                String respuesta = OpcionMenu.nextLine();
                               
                                String ConsolUpper = respuesta.toUpperCase();

                                if(ConsolUpper.equals("SI")){
                                    //Recibo la transaccion
                                    outStream.writeObject(true);
                                    transaction = (String)inStream.readObject();
                                    //Mando la transaccion firmada
                                    Signature signature = Signature.getInstance("MD5withRSA");
                                    signature.initSign(privateKey);
                                    byte[] buf = transaction.getBytes();
                                    
                                    signature.update(buf);
                                    outStream.writeObject(signature.sign());
                                   
                                }
                                else{
                                    outStream.writeObject(false);
                                }
                                System.out.println((String)inStream.readObject());
                            }
                        break;
                        case "wallet": case "w":
                            double saldo = (double)inStream.readObject();
                            System.out.println("El saldo actual es " + saldo);
                        break;
                        case "classify": case "c":
                            if((boolean)inStream.readObject()){
                                System.out.println("Vino clasificado correctamente");
                            }
                            else{
                                System.out.println("El vino no esta registrado en el catalogo");
                            }
                        break;
                        case "talk": case "t":
                            System.out.println((String)inStream.readObject());

                        break;
                        case "read": case "r":
                            
                           
                
                            String cad = "Para " + userID + ":" ;
                            List<String> mensajes  = new ArrayList<>();

                            Cipher c = Cipher.getInstance("RSA");
                            c.init(Cipher.DECRYPT_MODE,  privateKey);

                            FileInputStream fis;
                            FileOutputStream fos;
                            CipherInputStream cis;

                            fos = new FileOutputStream("aux.txt");
                            fis = new FileInputStream("communication.txt");
                            cis = new CipherInputStream(fis, c);

                            byte[] b = new byte[16];
                            int j = cis.read(b);
                            while(j != -1){
                                fos.write(b , 0 , j);
                                j = cis.read(b);
                            }

                            cis.close();
                            fis.close();
                            fos.close();

                            File communication = new File("./aux.txt");

                            Path thePath = Paths.get(communication.getAbsolutePath());
                            List<String> lines = Files.readAllLines(thePath, StandardCharsets.UTF_8);
                
                            FileWriter writer = new FileWriter(communication);


                
                            for(int i = 0 ; i < lines.size(); i++ ){
                                String line = lines.get(i);
                                if(line.contains(cad)){
                                    mensajes.add(line);
                                }
                                else{
                                    writer.write("\n" + lines.get(i));
                                }
                            }
                            
                            writer.close();
                
                
                            String cadena_salida = "";
                            
                            if(!mensajes.isEmpty()){
                                cadena_salida = "Tienes " + mensajes.size() + " mensajes:";
                                for(int i = 0  ; i < mensajes.size() ; i++){
                                    cadena_salida += "\n" + mensajes.get(i) ;
                                }
                            }
                            else{
                                cadena_salida = "No hay mensajes para leer";
                            }
                        
                            System.out.println(cadena_salida);

                            communication.delete();

                        break;
                    case "list": case "l":
                        System.out.println((String)inStream.readObject());
                    break;
                    default:
                            
        
                    }
                    
                    
                    consola = OpcionMenu.nextLine();
                    outStream.writeObject(consola);
                    estado = (boolean)inStream.readObject();
                }

                if(!estado) System.out.println("Opcion -" + consola + " incorrecta" );
                
                outStream.close();
                inStream.close();
                s.close();
                
            } catch (Exception e) {
                System.err.println(e.getMessage());
                System.exit(-1);
            }
           
        
        }
    }

