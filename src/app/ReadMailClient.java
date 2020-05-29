package app;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;

	private static final String USERB_KEYSTORE = "./data/userb-keystore.jks";
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, MessagingException, NoSuchPaddingException, InvalidAlgorithmParameterException, KeyStoreException, CertificateException, UnrecoverableKeyException {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\nMessage number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
	    
        //TODO: Decrypt a message and decompress it. The private key is stored in a file.
		Cipher aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
		//SecretKey secretKey = new SecretKeySpec(JavaUtils.getBytesFromFile(KEY_FILE), "AES");
		
		//Izvlacenje enkriptovane poruke, tajnog kljuca i inicijalizacionih vektora
		MailBody mailBody = new MailBody(MailHelper.getText(chosenMessage));
		IvParameterSpec ivParameterSpec1 = new IvParameterSpec(mailBody.getIV1Bytes());
		IvParameterSpec ivParameterSpec2 = new IvParameterSpec(mailBody.getIV2Bytes());
		byte[] secretKeyEnc = mailBody.getEncKeyBytes();
		String text = mailBody.getEncMessage();
		
		//Keystore
		char[] pwdArrayB = "userb".toCharArray();
		KeyStore ks = KeyStore.getInstance("JKS");
		
		BufferedInputStream in = new BufferedInputStream(new FileInputStream(USERB_KEYSTORE));
		ks.load(in, pwdArrayB);
		PrivateKey pk = (PrivateKey) ks.getKey("userb", pwdArrayB);
		
		Cipher rsaCipherDec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipherDec.init(Cipher.DECRYPT_MODE, pk);
		byte[] decryptedKey = rsaCipherDec.doFinal(secretKeyEnc);
		
		SecretKey secretKey = new SecretKeySpec(decryptedKey, "AES");
		System.out.println("Dekriptovan kljuc: " + secretKey.hashCode());
		
		//inicijalizacija za dekriptovanje
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec1);
		
		//dekompresovanje i dekriptovanje teksta
		String receivedBodyTxt = new String(aesCipherDec.doFinal(Base64.decode(text)));
		String decompressedBodyText = GzipUtil.decompress(Base64.decode(receivedBodyTxt));
		System.out.println("Body text: " + decompressedBodyText);
		
		//inicijalizacija za dekriptovanje
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec2);
		
		//dekompresovanje i dekriptovanje subject-a
		String decryptedSubjectTxt = new String(aesCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
		String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));
		System.out.println("Subject text: " + new String(decompressedSubjectTxt));
	}
}