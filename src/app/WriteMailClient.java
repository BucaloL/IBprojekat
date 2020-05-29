package app;


import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import com.google.api.services.gmail.Gmail;

import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {
	
	private static final String USERA_KEYSTORE = "./data/usera-keystore.jks";
	
	public static void main(String[] args) {
		
        try {
        	Gmail service = getGmailService();
            
        	System.out.println("Insert a reciever:");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String reciever = reader.readLine();
        	
            System.out.println("Insert a subject:");
            String subject = reader.readLine();
            
            System.out.println("Insert body:");
            String body = reader.readLine();
            
            
            //Compression
            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
            
            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
			SecretKey secretKey = keyGen.generateKey();
			Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
			
			//sifrovanje
			byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			//sifrovanje
			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
			
			//Keystore
			char[] pwdArrayA = "usera".toCharArray();
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(USERA_KEYSTORE), pwdArrayA);
			
			java.security.cert.Certificate userb_cer = ks.getCertificate("userb-cer");
			Key userb_key = userb_cer.getPublicKey();
			
			//inicijalizacija za sifrovanje 
			Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipherEnc.init(Cipher.ENCRYPT_MODE, userb_key);

			//sifrovanje
			byte[] cipherkey = rsaCipherEnc.doFinal(secretKey.getEncoded());
			String cipherkeyStr = Base64.encodeToString(cipherkey);
			System.out.println("Kljuc: " + secretKey.hashCode());
			System.out.println("Kriptovan kljuc: " + cipherkeyStr);
			
			MailBody mb = new MailBody(ciphertextStr, ivParameterSpec1.getIV(), ivParameterSpec2.getIV(), cipherkeyStr);
			String mailBody = mb.toCSV();
			System.out.println("Telo emaila: " + mailBody);
			
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, mailBody);
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
}