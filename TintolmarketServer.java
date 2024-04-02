import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;


import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;






public class TintolmarketServer{
    
    private int port;
	private File catalogue;
	private File sellers;
    private File users_saldo;
	private File communication;
	private String ruta = "";
    private String pasword_cifra ;
    private String keystore_name;
    private String password_keystore;
    private SecretKey key;
    private KeyStore keystore;
    private PrivateKey privateKey;
    private Certificate cer;
    private BlockChain blockChain;

    
   
    
    
    //Constructor vacio
    public TintolmarketServer(int port , String pswd_cifra , String ks , String ks_pswd) throws Exception{
        this.port = port;
        this.pasword_cifra = pswd_cifra;
        this.keystore_name = ks;
        this.password_keystore = ks_pswd;

        FileInputStream kfile = new FileInputStream(keystore_name);
        keystore = KeyStore.getInstance("PKCS12");
        keystore.load(kfile, password_keystore.toCharArray());
        privateKey = (PrivateKey)keystore.getKey("server", password_keystore.toCharArray());
        cer = keystore.getCertificate("server");
        blockChain = new BlockChain();
       
    }

    
    public static void main(String[] args)throws Exception{
        
        int port = 12345;
        int i = 0;
        if(args.length == 4){
            port = Integer.parseInt(args[0]);
            i++;
        }
        TintolmarketServer server = new TintolmarketServer(port , args[i],args[i+1],args[i+2]);

        server.startServer();
    }

    public void GenerateKeyPBE(String pswd) throws NoSuchAlgorithmException, InvalidKeySpecException{
        byte[] salt = { (byte) 0xc7, (byte) 0x86, (byte) 0x93, (byte) 0x9, (byte) 0x54, (byte) 0x3e, (byte) 0xfa, (byte) 0xf2 };
        // Generate the key based on the password
        PBEKeySpec keySpec = new PBEKeySpec(pasword_cifra.toCharArray(), salt, 20); // pass, salt, iterations
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        key = kf.generateSecret(keySpec);
       
    }

    public byte[] getParams() throws IOException{
        File fi = new File("params_store.txt");
        Path archivo = Paths.get(fi.getAbsolutePath());
        byte[] file_content = Files.readAllBytes(archivo);
        return file_content;
    }

    public void Cifra() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
        //gerar uma chave aleatória para utilizar com o AES

        Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
        c.init(Cipher.ENCRYPT_MODE, key);

        FileInputStream fis;
        FileOutputStream fos;
        CipherOutputStream cos;
        
        fis = new FileInputStream("users.txt");
        fos = new FileOutputStream("users.cif");

        cos = new CipherOutputStream(fos, c);
        byte[] b = new byte[16];  
        int i = fis.read(b);
        while (i != -1) {
            cos.write(b, 0, i);
            i = fis.read(b);
        }
        
        cos.close();
        fis.close();
        fos.close();

        File file = new File("users.txt");
        file.delete();

        byte [] params = c.getParameters().getEncoded();

        File fparams = new File("params_store.txt");
        FileOutputStream fo = new FileOutputStream(fparams);
        fo.write(params);
        fo.close();
    }
    
    public void Decifra() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException{
        AlgorithmParameters p = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_128");
        p.init(getParams());
        
        Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
        c.init(Cipher.DECRYPT_MODE,  key , p);

        FileInputStream fis;
        FileOutputStream fos;
        CipherInputStream cis;

        fos = new FileOutputStream("users.txt");
        fis = new FileInputStream("users.cif");
        cis = new CipherInputStream(fis, c);

        byte[] b = new byte[16];
        int i = cis.read(b);
        while(i != -1){
            fos.write(b , 0 , i);
            i = cis.read(b);
        }

        cis.close();
        fis.close();
        fos.close();
    }
   
    public  void startServer() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        //Creacion de la llave simetrica para cifrar
        GenerateKeyPBE(pasword_cifra);
        
           
        try {		
			File dir_actual = new File("");
			ruta = dir_actual.getAbsolutePath() + "/GalleryForServer/";

			File directorio = new File(ruta);
        	if (!directorio.exists()) {
            	if (directorio.mkdirs())
                	System.out.println("Directorio GalleryForServer creado");	
       		}
			

            users_saldo = new File("./users_saldo.txt");

            File users = new File("users.cif");
            if (!users.exists()) {
                File file = new File("users.txt");
                file.createNewFile();
                Cifra();
            }

            



			if (!users_saldo.exists()) {
                users_saldo.createNewFile();
            }

			catalogue = new File("./catalogue.txt");

			if (!catalogue.exists()) {
                catalogue.createNewFile();
            }

			sellers = new File("./sellers.txt");

			if (!sellers.exists()) {
                sellers.createNewFile();
            }

			communication = new File("./communication.txt");

			if (!communication.exists()) {
                communication.createNewFile();
            }
			
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

        //Creacion de la keystore para el server
        //keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore keystore.server

        //Properties correctamente definidas antes de la creacion del SSLServerSocket
        System.setProperty("javax.net.ssl.keyStore", keystore_name);
        System.setProperty("javax.net.ssl.keyStorePassword", password_keystore);
        

        //Creacion del socket servidor SSL
        ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
        SSLServerSocket sslServerSocket = (SSLServerSocket)ssf.createServerSocket(port);

        while(true){
            Socket socket = sslServerSocket.accept();
            ServerThread thread = new ServerThread(socket);//Una thread por cliente
            thread.start(); 
        }

        
        
    }

    class BlockChain {
        int n_trx; //Number of transactions of the block
        int blk_id; //Block id
        String ruta;
        String ruta_dir;
       
    
        public BlockChain() throws Exception{
            File dir_actual = new File("");
            ruta_dir = dir_actual.getAbsolutePath() + "/BlockChainStore/";
    
            File directorio = new File(ruta_dir);
            if (!directorio.exists()){
                if (directorio.mkdirs())
                    System.out.println("Directorio BlockChainStore creado");
                ruta = ruta_dir + "block_1.blk";
                n_trx = 0;
                blk_id = 1;	
                createNewBlock();
            }
            else{
               
                File[] blockchainFiles = directorio.listFiles();
                int numBlockchainFiles = 0;
    
                
    
                for (File blockchainFile : blockchainFiles) {
                    if (blockchainFile.isFile() && blockchainFile.getName().endsWith(".blk")) {
                        numBlockchainFiles++;
                        
                    }
                }
                if(numBlockchainFiles >= 1){
                

                
                    Map<Integer,String> idHash = new HashMap<>();
                    
                    for (File blockchainFile : blockchainFiles) {
                        if (blockchainFile.isFile() && blockchainFile.getName().endsWith(".blk")) {
                            Path path = Paths.get(blockchainFile.getAbsolutePath());
                            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
                            
                            //Guardamos el hash y el id y verificamos si la firma es correcta
                            String arr1[] = lines.get(2).split("=");
                            String [] arr = lines.get(1).split("=");
                          /*   if(Integer.parseInt(arr1[1]) == 5 && numBlockchainFiles > 1){
                                if(veryfySignBlock(blockchainFile, lines.get(8).getBytes())){
                                    System.out.println("Firma del blockchain " + arr[1] + " correcta");
                                }
                                else{
                                    throw new SignatureException("Firma del blockchain " + arr[1] + " incorrecta" );
                                }
                            } */                              
                            idHash.put(Integer.parseInt(arr[1]), lines.get(0));                  
                        }                             
                    }
                    String arch = ruta_dir + "block_" + 1 + ".blk";
                    File fi = new File(arch);
                    Path archivo = Paths.get(fi.getAbsolutePath());
                    List<String> lines = Files.readAllLines(archivo, StandardCharsets.UTF_8);
                    if(lines.get(0).equals("00000000")){
                        System.out.println("Cabecera del bloque 1 correcta");
                    }
                    else{
                        System.out.println("Cabecera del bloque 1 incorrecta");
                    }
                    /* No funciona
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    for(int i = numBlockchainFiles ; i > 1 ; i--){             
                        arch = ruta_dir + "block_" + (i-1) + ".blk";
                        fi = new File(arch);
                        archivo = Paths.get(fi.getAbsolutePath());
                        lines = Files.readAllLines(archivo, StandardCharsets.UTF_8);
                        byte[] file_content = Files.readAllBytes(archivo);                      
                        byte[] bhash = md.digest(file_content);
                        
                        BufferedReader br = new BufferedReader(new FileReader(ruta_dir + "block_" + (i) + ".blk"));
                        String hash = br.readLine();
                        byte[] hashBytes = hash.getBytes();
                        

                        if(MessageDigest.isEqual(bhash, hashBytes)){
                            System.out.println("hash del bloque " + i + " correcto");
                        }
                        else{
                            throw new Exception("Hash invalido");
                        }                       
                        
                    }*/
                }  
                 //Recovery del id , n_trx 
                 blk_id = numBlockchainFiles;
                 ruta = ruta_dir + "block_" + blk_id + ".blk";
                 File last_blk = new File(ruta);
                 Path path = Paths.get(last_blk.getAbsolutePath());
                 List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
                 String[] arr = lines.get(2).split("=");
                 n_trx = Integer.parseInt(arr[1]);
                 
            
            }   
    
        }
                // Función para convertir una cadena de texto con caracteres hexadecimales a un arreglo de bytes
        public  byte[] hexStringToByteArray(String s) {
            int len = s.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                    + Character.digit(s.charAt(i+1), 16));
            }
            return data;
        }
        String listAll() throws IOException{
            String result = "";
            File directorio = new File(ruta_dir);
            File[] blockchainFiles = directorio.listFiles();
            for (File blockchainFile : blockchainFiles) {
                if (blockchainFile.isFile() && blockchainFile.getName().endsWith(".blk")) {
                    Path path = Paths.get(blockchainFile.getAbsolutePath());
                    List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);  
                    String arr1[] = lines.get(2).split("=");

                    for(int i = 0 ; i < Integer.parseInt(arr1[1]) ; i++){
                        result += "\n" + lines.get(3+i);
                    }
                    
                }
            }
            return result;
        }
        boolean veryfySignBlock(File file ,byte[] signature) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, IOException{
            
            Path archivo = Paths.get(file.getAbsolutePath());
            byte[] file_content = Files.readAllBytes(archivo);

            Signature s = Signature.getInstance("MD5withRSA");
            s.initVerify(cer.getPublicKey());
            
            s.update(file_content);

    
            if (s.verify(signature))
                return true;
            
            return false;
        }

        public void createNewBlock() throws IOException, NoSuchAlgorithmException{
            System.out.println(ruta);
            File block = new File(ruta);
            FileOutputStream fo = new FileOutputStream(block);
            String header;
            if(blk_id == 1){        
                header = "00000000" + "\n" + 
                                "blk_id=" + blk_id + "\n" +
                                "n_trx=" + n_trx + "\n";                   
            }
            else{

                File file = new File(ruta_dir + "block_" + (blk_id-1) + ".blk" );
                header = getFileHash(file) + "\n" + 
                                "blk_id=" + blk_id + "\n" +
                                "n_trx=" + n_trx + "\n"; 
            }

            fo.write(header.getBytes());
            fo.close();
        }

        public byte[] getFileHash(File file) throws IOException, NoSuchAlgorithmException{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            Path archivo = Paths.get(file.getAbsolutePath());
            byte[] file_content = Files.readAllBytes(archivo);
    
           
            byte[] bhash = md.digest(file_content);
    
            
            return bhash;
        }

        public byte[] signFile() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException{
            File file = new File(ruta);
            Path archivo = Paths.get(file.getAbsolutePath());
            byte[] file_content = Files.readAllBytes(archivo);
            Signature s = Signature.getInstance("MD5withRSA");
            s.initSign(privateKey);
            s.update(file_content);
            return s.sign();
        }

        public void closeBlock() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException{
            File file = new File(ruta);
            FileWriter writer = new FileWriter(file,true);
            writer.write("\n" + signFile());
            blk_id++;
            n_trx = 1;
            ruta = ruta_dir + "block_" + blk_id + ".blk";
            writer.close();
        }

        public void addTransaction(String transaction) throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException{
            n_trx++;
            if((n_trx ) > 5){
                closeBlock();
                
                createNewBlock();
            }
            
            File file = new File(ruta);
            Path thePath = Paths.get(file.getAbsolutePath());
            List<String> lines = Files.readAllLines(thePath, StandardCharsets.UTF_8);
            
            String linea_trx = "n_trx=" + n_trx ;
            lines.set(2, linea_trx);

            FileWriter writer = new FileWriter(file);
            for (String line : lines) {
                writer.write(line + "\n");
            }
            int numberOfTransaction = n_trx + (blk_id-1)*5;
            writer.write("Transaction " + numberOfTransaction +  " " + transaction);
           
            writer.close();
            
        }
    }
    
    
    class ServerThread extends Thread {
        private Socket sock;
        private String userCertificate;
        private PublicKey publicKey;
        private String user;
        private ObjectOutputStream outStream ;
	    private ObjectInputStream inStream ;

        public ServerThread(Socket socket){
            sock = socket;
            try {
				outStream = new ObjectOutputStream(sock.getOutputStream());
				inStream = new ObjectInputStream(sock.getInputStream());
			} catch (IOException e) {
				e.printStackTrace();
			}
        }
        
        boolean isNew(String user) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidAlgorithmParameterException{
            Decifra();
			boolean _new = true;
			try {
				BufferedReader br = new BufferedReader(new FileReader("./users.txt"));
				String line;
				
				while ((line = br.readLine()) != null && _new) {
                    String [] _line = line.split("-");			
					if(_line[0].equals(user)){
						_new = false;
						userCertificate = _line[1];

					}
                }
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
            Cifra();
			return _new;
		}

        boolean Menu(String option) throws IOException, ClassNotFoundException, InvalidKeyException, NumberFormatException, NoSuchAlgorithmException, SignatureException, CertificateException, NoSuchPaddingException{
			boolean aux = true;
			String [] arr = option.split(" ");
			switch(arr[0]){
				case "add": case "a":
					try {
						outStream.writeObject(true);
						if(NotNewWine(arr[1])){
                            outStream.writeObject(true);
							add(arr[1],arr[2]);
						}
						else{
							outStream.writeObject(false);
						}
						
						
						
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				break;
				case "sell": case "s":
					try {
						outStream.writeObject(true);
						sell(arr[1], Double.parseDouble(arr[2]),Integer.parseInt(arr[3]));
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				break;
				case "view": case "v":
					outStream.writeObject(true);
					outStream.writeObject(view(arr[1]));
				break;
				case "buy": case "b":
					outStream.writeObject(true);
					buy(arr[1], arr[2], Integer.parseInt(arr[3]));
				break;
				case "wallet": case "w":
					outStream.writeObject(true);
					wallet();
				break;
				case "classify": case "c":
					outStream.writeObject(true);
					classify(arr[1], Double.parseDouble(arr[2]));
				break; 
				case "talk": case "t":
					outStream.writeObject(true);
					int indice = arr[0].length() + arr[1].length()+2;
					String s = option;
					String msg = s.substring(indice);
					outStream.writeObject(talk(arr[1], msg));
				break;
				case "read": case "r":
					outStream.writeObject(true);
				break;
                case "list": case "l":
                    outStream.writeObject(true);
                    outStream.writeObject(blockChain.listAll());
                break;
				case "exit": case"e":
					outStream.writeObject(false);
					aux = false;
				break;
				default:
					outStream.writeObject(false);
					aux = false;

			}

			return aux;
		}
		public boolean NotNewWine(String wine){
			
            boolean _new = true;
			try {
				BufferedReader br = new BufferedReader(new FileReader(catalogue));
				String line;
				while ((line = br.readLine()) != null && _new) {
                    String [] _line = line.split("-");
					if(_line[0].equals(wine)){
						_new = false;
					}
                }
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return _new;
		}		
		public boolean buy(String wine , String seller , int quantity) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, ClassNotFoundException{
			double saldo_user = 0;
			double saldo_seller = 0;
			int cantidad = 0;
			double precio  = 0;
			boolean isInSeller = false;

			//Compruebo si el vino esta en el catalogo
			if(NotNewWine(wine)){
				outStream.writeObject("El vino a comprar no esta en el catalogo");
                outStream.writeObject(false);
				return false;
			}
			
			//Obtengo el saldo del usuario que va a comprar y del vendedor
			
			try {
				BufferedReader br = new BufferedReader(new FileReader(users_saldo));
				String line;
				while ((line = br.readLine()) != null) {
                    String [] _line = line.split("-");
					if(_line[0].equals(user)){
						saldo_user = Double.parseDouble(_line[1]);
					}
					if(_line[0].equals(seller)){
						saldo_seller = Double.parseDouble(_line[1]);
					}
                }
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

			//Busco si esta el vino en venta y me guardo los atributos cantidad y precio
			try {
				BufferedReader br = new BufferedReader(new FileReader(sellers));
				String line;
				
				while ((line = br.readLine()) != null ) {
                    String [] _line = line.split("-");
					if(_line[0].equals(seller) && _line[1].equals(wine)){
						isInSeller = true;
						cantidad = Integer.parseInt(_line[2]);
						precio = Double.parseDouble(_line[3]);
					}
                }
				br.close();

			} catch (IOException e) {
				e.printStackTrace();
			}

			if (!isInSeller){
				outStream.writeObject("El vino a comprar no esta en venta");
                outStream.writeObject(false);
				return false;
			}
			
			if(cantidad < quantity){
				outStream.writeObject("No se puede efectuar la compra porque no hay cantidad suficiente");
                outStream.writeObject(false);
				return false;
			}
			if(saldo_user < quantity*precio){
				outStream.writeObject("No se puede efectuar la compra porque no hay saldo suficiente");
                outStream.writeObject(false);
				return false;
			}

            String transaction = wine + "--" + quantity + "--" + precio + "--" + user;
            outStream.writeObject("La transaccion que se va a realizar es esta: \n" +
                                    transaction + "\n" +
                                    "Desea realizar la operacion? Si/no-->"    ); 
            outStream.writeObject(true);
            boolean Seguir = (boolean)inStream.readObject();
            if(Seguir){
                outStream.writeObject(transaction);
                byte[] firma = (byte[])inStream.readObject();
                //Verifico la firma
                Signature s = Signature.getInstance("MD5withRSA");
                s.initVerify(publicKey);
                byte[] buf = transaction.getBytes();
                s.update(buf);

                //verificacion
                if (s.verify(firma)){
                    blockChain.addTransaction(transaction);
    
                    Path thePath = Paths.get(users_saldo.getAbsolutePath());
                    List<String> lines = Files.readAllLines(thePath, StandardCharsets.UTF_8);
    
                    
                    for(int i = 0 ; i < lines.size(); i++ ){
                        String line = lines.get(i);
                        String [] line_split = line.split("-");
                        String aux = "";
                        if(line_split[0].equals(seller)){
                            double nuevaSaldo = saldo_seller + precio*quantity;
                            aux = line_split[0] + "-" +  nuevaSaldo ;
                            lines.set(i, aux);
                            
                        }
                        if(line_split[0].equals(user)){
                            double nuevaSaldo = saldo_user - precio*quantity;
                            aux = line_split[0] + "-" +  nuevaSaldo ;
                            lines.set(i, aux);
                            
                        }
                    }
    
                    FileWriter writer = new FileWriter(users_saldo);
                    for (String line : lines) {
                        writer.write(line + "\n");
                    }
                    writer.close();
                    
                    
    
                    thePath = Paths.get(sellers.getAbsolutePath());
                    lines = Files.readAllLines(thePath, StandardCharsets.UTF_8);
    
                    boolean seguir = true;
                    for(int i = 0 ; i < lines.size() && seguir; i++ ){
                        String line = lines.get(i);
                        String [] line_split = line.split("-");
                        String aux = "";
                        if(line_split[0].equals(seller) && line_split[1].equals(wine)){
                            int nuevaCant = cantidad - quantity;
                            aux = line_split[0] + "-" + line_split[1] + "-" +  nuevaCant + "-" + precio ;
                            lines.set(i, aux);
                            seguir = false;
                        }
                        
                    }
                    
                    writer = new FileWriter(sellers);
                    for (String line : lines) {
                        writer.write(line + "\n");
                    }
                    writer.close();
                    
    
                    thePath = Paths.get(catalogue.getAbsolutePath());
                    lines = Files.readAllLines(thePath, StandardCharsets.UTF_8);
    
                    seguir = true;
                    for(int i = 0 ; i < lines.size() && seguir; i++ ){
                        String line = lines.get(i);
                        String [] line_split = line.split("-");
                        String aux = "";
                        if(line_split[0].equals(wine)){
                            int nuevaCant = Integer.parseInt(line_split[2]) - quantity;
                            aux = line_split[0] + "-" + line_split[1] + "-" +  nuevaCant + "-" + line_split[2];
                            lines.set(i, aux);
                            seguir = false;
                        }
                        
                    }
                    
                    writer = new FileWriter(catalogue);
                    for (String line : lines) {
                        writer.write(line + "\n");
                    }
                    writer.close();
    
                
    
    
                    outStream.writeObject("Compra realizada correctamente");
                    
                }
                else{
                    outStream.writeObject("Error al verificar la firma , no se pudo realizar la operacion");
                    
                }
            }
            else{
                outStream.writeObject("...Operacion Cancelada...");
            }
            
			
            
            
            return true;    
            
		}
		public void add(String wine , String fileImage) throws IOException, ClassNotFoundException { 
			
			FileOutputStream fout;
			
			fout = new FileOutputStream(catalogue , true);
			
			String linea = "\n" + wine + "-" + fileImage + "-0" + "-0"  ;
			byte[] bytes = linea.getBytes();
	
			fout.write(bytes);
			fout.close();
			outStream.writeObject(true);
			/* 
			Usamos el flujo de salida InStream para leer los
			datos del archivo a traves del socket */
			
			File imagen = new File(ruta + fileImage);
			BufferedInputStream bis = new BufferedInputStream(sock.getInputStream());
			BufferedOutputStream bos  = new BufferedOutputStream(new FileOutputStream(imagen));
			

			int size = (Integer)inStream.readObject();
			byte [] buffer = new byte[size];
			int bytesLeidos = bis.read(buffer);
			

			//Escribimos los datos recibidos en el objeto File

			
			bos.write(buffer, 0, bytesLeidos);
				
			

			//bis.close();
			
			bos.close();			
			
		}
		public void wallet() throws IOException{
			boolean encontrado = false;
			try {
				BufferedReader br = new BufferedReader(new FileReader(users_saldo));
				String line;
				while ((line = br.readLine()) != null && !encontrado) {
                    String [] _line = line.split("-");
					if(_line[0].equals(user)){
						outStream.writeObject(Double.parseDouble(_line[1]));
						encontrado = true;
					}
                }
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		
		}
		public void sell(String wine , double value , int quantity) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, ClassNotFoundException{
			if(!NotNewWine(wine)){
				FileOutputStream fout;
				fout = new FileOutputStream(sellers , true);
				
				String linea = "\n" + user + "-" + wine + "-" + quantity  + "-" + value  ;
                String transaction = wine + "--" + quantity + "--" + value + "--" + user;
                outStream.writeObject(true);
                outStream.writeObject(transaction);
                boolean seguir = (boolean)inStream.readObject();
                if(seguir){
                    //Transacion firmada 
                    byte[] firma = (byte[])inStream.readObject();
                    //Verifico la firma
                    Signature s = Signature.getInstance("MD5withRSA");
                    s.initVerify(publicKey);
                    byte[] buf = transaction.getBytes();
                    s.update(buf);

                    if (s.verify(firma)){
                        blockChain.addTransaction(transaction);
                        byte[] bytes = linea.getBytes();
                        fout.write(bytes);
                        fout.close();

                        Path thePath = Paths.get(catalogue.getAbsolutePath());
                        List<String> lines = Files.readAllLines(thePath, StandardCharsets.UTF_8);

                        boolean encontrado = false;
                        for(int i = 0 ; i < lines.size() && !encontrado ; i++ ){
                            String line = lines.get(i);
                            String [] line_split = line.split("-");
                            String aux = "";
                            if(line_split[0].equals(wine)){
                                int nuevaCantidad = Integer.parseInt(line_split[2]) + quantity ;
                                aux = line_split[0] + "-" + line_split[1] + "-" +  nuevaCantidad + "-" +  line_split[3];
                                lines.set(i, aux);
                                encontrado = true;
                            }
                        }

                        FileWriter writer = new FileWriter(catalogue);
                        for (String line : lines) {
                            writer.write(line + "\n");
                        }
                        writer.close();
                        outStream.writeObject(true);
                    }
                    else{
                        outStream.writeObject(false);
                    }
                                       
			    }
            }
			else{
				outStream.writeObject(false);
			}
		}
		public void classify(String wine , double stars) throws IOException{
			
			Path thePath = Paths.get(catalogue.getAbsolutePath());
			List<String> lines = Files.readAllLines(thePath, StandardCharsets.UTF_8);

			boolean encontrado = false;
			for(int i = 0 ; i < lines.size() && !encontrado ; i++ ){
				String line = lines.get(i);
				String [] line_split = line.split("-");
				String aux = "";
				if(line_split[0].equals(wine)){
					double new_star;
					if(line_split[3].equals("0")){
						new_star = stars;
					}
					else{
						new_star = (Double.parseDouble(line_split[3])+stars)/2.0;
					}
					aux = line_split[0] + "-" + line_split[1] + "-" + line_split[2] + "-" +  new_star;
					lines.set(i, aux);
					encontrado = true;
				}
			}
			if(encontrado){
				FileWriter writer = new FileWriter(catalogue);
				for (String line : lines) {
					writer.write(line + "\n");
				}
				writer.close();
				outStream.writeObject(true);
			}
			
		}
		public String view(String wine) throws IOException{
			int cantidad_vino = 0;
			double clasif = 0;
			String mensaje = "";
			String file_image = "";
			Path thePath = Paths.get(catalogue.getAbsolutePath());
			List<String> lines = Files.readAllLines(thePath, StandardCharsets.UTF_8);

			boolean encontrado = false;
			for(int i = 0 ; i < lines.size() && !encontrado ; i++ ){
				String line = lines.get(i);
				String [] line_split = line.split("-");
				if(line_split[0].equals(wine)){
					cantidad_vino = Integer.parseInt(line_split[2]);
					clasif = Double.parseDouble(line_split[3]);
					file_image = line_split[1];
					encontrado = true;
				}
			}
			outStream.writeObject(encontrado);
			
			if(encontrado){
				outStream.writeObject(file_image);
				File imagen = new File(ruta + file_image);
				BufferedInputStream bis = new BufferedInputStream(new FileInputStream(imagen));
                BufferedOutputStream bos = new BufferedOutputStream(sock.getOutputStream());
				byte [] fileData =  bis.readAllBytes();
				
				//Enviamos el tamaño del archivo
				outStream.writeObject(fileData.length);
				
				// Enviamos los datos del archivo al servidor
				bos.write(fileData);
				bos.flush(); // Aseguramos que se envíe todo lo que hay en el buffer
				mensaje += "La imagen del vino ha sido guardada en su directorio personal /" + user + "\nHay " + cantidad_vino + " unidades de este vino con una clasificacion media de " +
				clasif + " y son vendidas por: ";
			}
			else{
				return "El vino no existe en el catalogo";
			}

			//Si hay existencias de vino y existe en el catalogo , buscamos sus vendedores

			thePath = Paths.get(sellers.getAbsolutePath());
			lines = Files.readAllLines(thePath, StandardCharsets.UTF_8);

			for(int i = 0 ; i < lines.size(); i++ ){
				String line = lines.get(i);
				if(!line.equals("")){
					String [] line_split = line.split("-");
				
					if(line_split[1].equals(wine)){
						mensaje += "\n " + line_split[0] + "---> " + line_split[2] + " unidades a " + line_split[3] + " la botella";
					}
				}
				
			}
			return mensaje;
		}
        
		public String talk(String receptor , String message) throws IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
			String ruta = receptor + ".cer";
            FileInputStream fis = new FileInputStream(ruta); 
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            Certificate cert = cf.generateCertificate(fis);

            PublicKey pk = cert.getPublicKey();
            
            
            //Receptor: Mensaje de user : "message"

			//Primero compruebo que el receptor existe
			String rt = "";
			Path thePath = Paths.get(users_saldo.getAbsolutePath());
			List<String> lines = Files.readAllLines(thePath, StandardCharsets.UTF_8);

			boolean existe = false;
			for(int i = 0 ; i < lines.size() && !existe ; i++ ){
				String line = lines.get(i);
				String [] line_split = line.split("-");
				if(line_split[0].equals(receptor)){
					existe = true;
				}
			}
			if(!existe){
				return "El usuario " + receptor + " no existe\n";
			}

            Cipher c = Cipher.getInstance("RSA");
            c.init(Cipher.ENCRYPT_MODE, pk);
        
           
            FileOutputStream fos;
            CipherOutputStream cos;
            
            
            fos = new FileOutputStream("communication.txt");
        
            cos = new CipherOutputStream(fos, c);
            
            String msg = "";
			msg = "\nPara " + receptor + ":" + "\tMensaje de " + user + " ---> " + message;
            cos.write(msg.getBytes());            
            
            cos.close();
            fis.close();
            fos.close();
			
			return "Mensaje cifrado enviado al usuario " + receptor + " correctamente\n";

		}
        boolean veryfySign(PublicKey pk , long nonce , byte[] signature) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException{

            Signature s = Signature.getInstance("MD5withRSA");
            s.initVerify(pk);
            byte[] buf = new byte[8];
            for (int i = 0; i < 8; i++) {
                buf[i] = (byte)(nonce >> (i * 8));
            }
            s.update(buf);

            if (s.verify(signature))
                return true;
            
            return false;
        }
        public void run(){
            try {
                System.out.println(sock);
                user = (String)inStream.readObject();
                System.out.println("Thread del servidor para atender al cliente " + user);
                //Verifico si esta y envio el flag
                //COMPLETAR
                // Verifica si el usuario está registrado y envía el nonce y la flag correspondientes
                Random  rnd = new Random();
                long nonce = rnd.nextLong();

                Boolean flag;

                if(isNew(user)) flag = false;
                else flag = true;

                outStream.writeObject(nonce);
                outStream.writeObject(flag);
                byte[] signature;
                if(flag){
                    signature = (byte[])inStream.readObject();
                    //Usamos la llave publica asociada a userID
                    FileInputStream fis = new FileInputStream(userCertificate);
                    CertificateFactory cf = CertificateFactory.getInstance("X509");
                    Certificate cert = cf.generateCertificate(fis);
                    publicKey = cert.getPublicKey();
                    if(veryfySign(publicKey,nonce ,signature))
                        System.out.println("El usuario estaba registrado , y su firma digital es correcta");
                    else
                        System.out.println("ERROR:El usuario estaba registrado , y su firma digital no es correcta");    
                }
                else{
                    signature = (byte[])inStream.readObject();  
                    long rnonce = (long)inStream.readObject();
                    Certificate cer = (Certificate)inStream.readObject();  
                    publicKey = cer.getPublicKey();
                    //Verificamos si la firma digital es correcta y si el nonce es el mismo
                    if(rnonce == nonce){
                        if(veryfySign(publicKey,rnonce ,signature)){
                            Decifra();
                            File users = new File("./users.txt");
                            FileOutputStream fout = new FileOutputStream(users , true);
                            String nombre_cer = "./" + user + ".cer";
                            File certificado = new File(nombre_cer);
                            FileOutputStream fo = new FileOutputStream(certificado);
                            fo.write(cer.getEncoded());
                            
                            String linea = "\n" + user + "-" + certificado ;
                            byte[] bytes = linea.getBytes();

                            fout.write(bytes);
                            fo.close();
                            Cifra();

                            System.out.println("Usuario correctamente registrado");
                            
                          
						
						
                            FileOutputStream fout1 = new FileOutputStream(users_saldo , true);
                            String linea1 = "\n" + user + "-" + "200";
                            byte[] bytes1 = linea1.getBytes();
                            
                            outStream.writeObject(true);

                            fout1.write(bytes1);
                            fout1.close();
                            fout.close();
                            
                        }
                    }
                }

                String option = (String)inStream.readObject();
                boolean seguir = Menu(option);
                
                while(seguir){
                    option = (String)inStream.readObject();
                    seguir = Menu(option);
                    
                }

            } catch (ClassNotFoundException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (SignatureException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (CertificateEncodingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (CertificateException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }



            //outStream.close();
				try {
                    inStream.close();
                    sock.close();
        
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
				


        }
    
        



    
    }
  
       
}

/* 
class VerifyIntegrity{

    private static File f;
    private static MessageDigest md;
    private static VerifyIntegrity instance = null;
     
    private VerifyIntegrity() throws NoSuchAlgorithmException, IOException{
        f = new File("HashingStore.txt");
        md = MessageDigest.getInstance("SHA");
        if(f.length() == 0){ //El archivo esta vacio , crearemos la estructura del almacen
            String structure = "catalogue.txt"  + "-" + getFileHash(new File("./catalogue.txt")) + "\n" 
                                + "sellers.txt" + "-" + getFileHash(new File("./sellers.txt")) + "\n"
                                + "communication.txt" + "-" + getFileHash(new File("./communication.txt"));
        }

           
    }

    public static VerifyIntegrity getInstance() throws NoSuchAlgorithmException, IOException{
        if(instance == null){
            instance = new VerifyIntegrity();
        }
        return instance;
    }

    public String getFileHash(File file) throws IOException, NoSuchAlgorithmException{
        Path archivo = Paths.get(file.getAbsolutePath());
        byte[] file_content = Files.readAllBytes(archivo);

       
        byte[] bhash = md.digest(file_content);

        String shash = new String(bhash);
        return shash;
    }

    public byte[] getOriginalHash(String file) throws IOException{
        Path path = Paths.get(f.getAbsolutePath());
	    List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        String originalHash = "";
        boolean seguir = true;
        for(int i = 0 ; i < lines.size() && seguir; i++ ){
            String line = lines.get(i);
            String [] line_split = line.split("-");
            
            if(line_split[0].equals(file)){
                seguir = false;
                originalHash = line_split[1];
            }
            
        }
        return originalHash.getBytes();
    }

    public boolean isCorrupted(File file) throws IOException, NoSuchAlgorithmException{
        boolean isCorrupted = true;
        byte[] originHash = getOriginalHash(file.getName());
        byte[] actualHash = getFileHash(file).getBytes();

        if(MessageDigest.isEqual(originHash, actualHash)) isCorrupted = false;

        return isCorrupted;
    }

    //Actualizar el hash de un archivo que he modificado con permiso para obtener su nuevo valor
    public void newHash(File file) throws IOException, NoSuchAlgorithmException{
        
        Path path = Paths.get(f.getAbsolutePath());
	    List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        String originalHash = "";
        boolean seguir = true;
        for(int i = 0 ; i < lines.size() && seguir; i++ ){
            String line = lines.get(i);
            String [] line_split = line.split("-");
            String aux_line = file.getName() + "-" + getFileHash(file);
            if(line_split[0].equals(file.getName())){
                lines.set(i, aux_line);
                seguir = false;
            }
            
        }

        FileWriter writer = new FileWriter(f);
			for (String line : lines) {
				writer.write(line + "\n");
			}
			writer.close();
    }
}
 */


        



