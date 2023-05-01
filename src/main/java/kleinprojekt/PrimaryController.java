package kleinprojekt;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.input.DragEvent;
import javafx.scene.input.MouseEvent;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.AnchorPane;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;

public class PrimaryController {

	private String activeTab = "encrypt";
	private int maxFileSize = 2 * (1024 * 1024);
	private int chunkSize = 16;
	private int offset = 0;
	private ByteArrayOutputStream baos = null;
	private String regex = new Regex().getRegex0();
	private Alert alert;
	private List<File> files = new ArrayList<File>();
	private String[] ciphers = { "AES", "RSA", "TripleDES" };
	private Cipher cipher = null;
	private byte[] encryptedFile = null;
	private byte[] decryptedFile = null;
	private byte[] key;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private SecretKeySpec secretKeySpec;
	
	@FXML
	private AnchorPane MainPane;
	
	@FXML
	private Button EnDecrypbtn;
	
	@FXML
	private Button savebtn;
	
	@FXML
	private Button encryptbtn;
	
	@FXML
	private Button decryptbtn;
	
	@FXML
	private Button createPasswordbtn;
	
	@FXML
	private ComboBox<String> CbCipher;
	
	@FXML
	private TextField tfPassword;
	
	@FXML
	private Label FilesEncryptDecryptSurface;
    
	@FXML
	void initialize() throws Exception {
		encryptbtn.setStyle("-fx-background-color: #ffd866; -fx-font-weight: bold;");
		encryptbtn.setUnderline(true);
		activeTab = "encrypted";
		FilesEncryptDecryptSurface.setText("File/s to encrypt");
		createPasswordbtn.setText("🔑");
		createPasswordbtn.setDisable(true);
		tfPassword.setDisable(true);
		savebtn.setVisible(false);
		EnDecrypbtn.setVisible(true);
		EnDecrypbtn.getStyleClass().add("stripes");
		tfPassword.getStyleClass().add("txt-pw");
		CbCipher.getItems().addAll(ciphers);
		cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
		alert = new Alert(AlertType.NONE);
		// still buggy: idk what the problem here is
		CbCipher.getSelectionModel().selectedIndexProperty().addListener((args, oldVal, newVal) -> {
			try {
				if (tfPassword.getText().isEmpty() || files.size() < 1 || CbCipher.getSelectionModel().isEmpty()) {
					EnDecrypbtn.getStyleClass().remove("stripes");
					EnDecrypbtn.getStyleClass().add("btn-red");
				} else {
					EnDecrypbtn.getStyleClass().remove("btn-red");
					EnDecrypbtn.getStyleClass().add("stripes");
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		});
	}
	
	@FXML
	void decrypt(ActionEvent event) throws Exception {
		encryptbtn.setStyle("-fx-background-color: #fae580; -fx-font-weight: normal;");
		encryptbtn.setUnderline(false);
		decryptbtn.setStyle("-fx-background-color: #ffd866; -fx-font-weight: bold;");
		decryptbtn.setUnderline(true);
		EnDecrypbtn.setText("Decrypt");
		EnDecrypbtn.setVisible(true);
		savebtn.setVisible(false);
		FilesEncryptDecryptSurface.setText("File to decrypt");
		tfPassword.setPrefWidth(200);
		tfPassword.clear();
		createPasswordbtn.setVisible(false);
		activeTab = "decrypted";
		CbCipher.getSelectionModel().clearSelection();
	}

	@FXML
	void encrypt(ActionEvent event) throws Exception {
		encryptbtn.setStyle("-fx-background-color: #ffd866; -fx-font-weight: bold;");
		encryptbtn.setUnderline(true);
		decryptbtn.setStyle("-fx-background-color: #fae580; -fx-font-weight: normal;");
		decryptbtn.setUnderline(false);
		EnDecrypbtn.setText("Encrypt");
		EnDecrypbtn.setVisible(true);
		savebtn.setVisible(false);
		FilesEncryptDecryptSurface.setText("File/s to encrypt");
		tfPassword.setPrefWidth(165);
		tfPassword.clear();
		createPasswordbtn.setVisible(true);
		activeTab = "encrypted";
		CbCipher.getSelectionModel().clearSelection();
	}
	
	@FXML
	void handleDragOver(DragEvent event) {
		if (event.getDragboard().hasFiles()) event.acceptTransferModes(TransferMode.ANY);
	}
	
	@FXML
	void handleDrop(DragEvent event) {
		if (activeTab.equals("encrypted")) {
			files = event.getDragboard().getFiles();
			if (files.isEmpty()) {
				alert(AlertType.ERROR, "No Files fetched!");
				return;
			}
			else {
				enablePasswordInputs();
				FilesEncryptDecryptSurface.setText("File/s to encrypt ✅");
			}
		} else if (activeTab.equals("decrypted")){
			files = event.getDragboard().getFiles();
			if (files.isEmpty()) {
				alert(AlertType.ERROR, "No File fetched!");
				return;
			} else if (files.get(0).getName().indexOf(".encrypted") == -1) {
				alert(AlertType.WARNING, "Please select an encrypted File");
				return;
			} else if (files.get(0).length() > maxFileSize) {
				alert(AlertType.WARNING, "Large file sizes might crash the application \nPlease select smaller files.");
				return;
			} else if (files.size() != 1) {
				alert(AlertType.WARNING, "Please select one File to decrypt!");
				return;
			} else {
				enablePasswordInputs();
				FilesEncryptDecryptSurface.setText("File to Decrypt ✅");		
			}
		}
	}
	
	@FXML
	void handleHover(MouseEvent event) {
		FilesEncryptDecryptSurface.setStyle("-fx-background-color: #f1bc31; -fx-text-fill: white; -fx-border-color: #f1bc31;");
	}
	
	@FXML
	void handleExited(MouseEvent event) {
		FilesEncryptDecryptSurface.setStyle("-fx-backgorund-color: transparent; -fx-text-fill: #f1bc31; -fx-border-color: #f1bc31;");
	}
	
	@FXML
	void mouseHover(MouseEvent event) {
		createPasswordbtn.setStyle("-fx-background-color: #f1bc31; -fx-text-fill: white; -fx-border-color: #f1bc31;");
	}
	
	@FXML
	void mouseExit(MouseEvent event) {
		createPasswordbtn.setStyle("-fx-background-color: transparent; -fx-text-fill: #f1bc31; -fx-border-color: #f1bc31;");
	}
	
	@FXML
	void handlePressed(MouseEvent event) {
		FileChooser fChooser = new FileChooser();
		if (activeTab.equals("decrypted")) {
			FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("ENCRYPTED File (*.encrypted)", "*.encrypted");
			fChooser.getExtensionFilters().add(extFilter);
			files = fChooser.showOpenMultipleDialog(null);
			if (files.isEmpty()) {
				alert(AlertType.ERROR, "No File fetched!");
				return;
			} else if (files.size() != 1) {
				alert(AlertType.WARNING, "Please select one File to decrypt!");
				return;
			} else if (files.get(0).length() > maxFileSize) {
				alert(AlertType.WARNING, "Large file sizes might crash the application \nPlease select smaller files.");
				return;
			} else {
				enablePasswordInputs();
				FilesEncryptDecryptSurface.setText("File to Decrypt ✅");
			}
		} else if (activeTab.equals("encrypted")) {
			files = fChooser.showOpenMultipleDialog(null);
			if (files.isEmpty()) {
				alert(AlertType.ERROR, "No File fetched!");
				return;
			}
			else {
				enablePasswordInputs();
				FilesEncryptDecryptSurface.setText("File/s to encrypt ✅");
			}
		}
	}
	
	@FXML
	void generatePassword(ActionEvent event) {	 
		tfPassword.setText(generateRandomPassword());
		passwordInputChange();
	 }
	
	@FXML
	void crypt(MouseEvent event) {
		if (tfPassword.getText().isEmpty() || files.size() < 1 || CbCipher.getSelectionModel().isEmpty()) {
			EnDecrypbtn.setVisible(true);
			savebtn.setVisible(false);	
		}
		else {
			EnDecrypbtn.setVisible(false);
			savebtn.setVisible(true);
		}
	}
	
    @FXML
    void saveClicked(MouseEvent event) throws Exception {
    	disableAll();
    	String password = tfPassword.getText();
		File zipFile = null;
		FileOutputStream fos = null;
		FileInputStream fis = null;
		ZipOutputStream zos = null;
		ZipInputStream zis = null;
		BufferedInputStream bis = null;
		byte[] data = null;
		DirectoryChooser dirChooser = new DirectoryChooser();
		if (files == null) {
			if (activeTab.equals("encrypted")) {
				alert(AlertType.WARNING, "Please select a file to encrypt!");
				return;
			} else if (activeTab.equals("decrypted")) {
				alert(AlertType.WARNING, "Please select a file to decrypt!");
				return;
			}
		} else if (password.isEmpty()) {
			alert(AlertType.WARNING, "Please enter a Password");
			return;
		} else if (!checkValidPassword(password)) {
			alert(AlertType.WARNING, "Password invalid please enter a Password");
			return;
		} else {
			File dirFile = dirChooser.showDialog(null);
			if (activeTab.equals("encrypted")) {
				if(files.size() > 1) {
					zipFile = new File(dirFile + "\\cryptedZipFile.zip");
					fos = new FileOutputStream(zipFile);
					zos = new ZipOutputStream(fos);
					for (File f : files) zipFile(f, zos);
					zos.close();
				} else {
					zipFile = new File(dirFile + "\\" + (files.get(0).getName() + ".zip"));
					fos = new FileOutputStream(zipFile);
					zos = new ZipOutputStream(fos);
					zipFile(files.get(0), zos);
					zos.close();
				}
				fis = new FileInputStream(zipFile);
				data = new byte[(int) zipFile.length()];
				bis = new BufferedInputStream(fis);
				bis.read(data, 0, data.length);
				fis.close();
				
				String cipher = CbCipher.getSelectionModel().getSelectedItem();
			
				if (checkValidPassword(password)) {
					switch (cipher) {
					case "AES":
						encryptedFile = aesEncryption(data, password);
						break;
					
					case "RSA":
						generateKey();
						encryptedFile = rsaEncryption(data);
						break;
					
					case "TripleDES":
						encryptedFile = tripleDESEncryption(data, password);
						break;
					}
				}
				
				String encryptedFileName = files.size() > 1 ? "cryptedZipFile.encrypted" : files.get(0).getName() + ".encrypted";
				
				try (FileOutputStream foss = new FileOutputStream(dirFile + "\\" + encryptedFileName)) {
					foss.write(encryptedFile);
				}
				
				alert(AlertType.INFORMATION, "File encrypted successfully");
				files = new ArrayList<File>();
				zipFile.delete();
				
			} else if (activeTab.equals("decrypted")) {
				if (files.size() != 1) {
					alert(AlertType.WARNING, "Please select a file to decrypt");
					return;
				}
				
				String encFileName = files.get(0).getName();
				if (!encFileName.endsWith(".encrypted")) {
					alert(AlertType.WARNING, "Please select a valid encrypted file!");
					return;
				}
				
				String decFileName = encFileName.substring(0, encFileName.length() - 10);
				File decFile = new File(dirFile, decFileName);
				if (decFile.exists()) {
					alert(AlertType.WARNING, "File already exists! Please choose a different name.");
					return;
				}
				fis = new FileInputStream(files.get(0));
				byte[] encryptedData = fis.readAllBytes();
				String cipher = CbCipher.getSelectionModel().getSelectedItem();
				if (checkValidPassword(password)) {
					switch (cipher) {
					case "AES":
						decryptedFile = aesDecryption(encryptedData, password);
						break;
					
					case "RSA":
						decryptedFile = rsaDecryption(encryptedData);
						break;
					
					case "TripleDES":
						decryptedFile = tripleDESDecryption(encryptedData, password);
						break;
					}
				}
				fos = new FileOutputStream(decFile);
				fos.write(decryptedFile);
				fos.close();
				
				//still in progress: either the decryption or the Code itself is broken idk
				unzipFile(zipFile, zis, fos, decFile);
				
				alert(AlertType.INFORMATION, "File decrypted successfully");
				files = new ArrayList<File>();
			}
			
		}
    }
	
	private void zipFile(File file, ZipOutputStream zos) throws IOException {
		BufferedInputStream bis = null;
		try {
			bis = new BufferedInputStream(new FileInputStream(file), maxFileSize);
			ZipEntry entry = new ZipEntry(file.getName());
			zos.putNextEntry(entry);
			byte data[] = new byte[maxFileSize];
			int count;			
			while ((count = bis.read(data, 0, maxFileSize)) != -1) zos.write(data, 0, count);	
			zos.closeEntry();
		} finally {
			try {
				bis.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	private void unzipFile(File zipFile, ZipInputStream zis, FileOutputStream fos, File outputFolder) throws IOException {
	    zis = new ZipInputStream(new FileInputStream(zipFile));
	    ZipEntry ze = zis.getNextEntry();
	    byte[] buffer = new byte[1024];
	    while (ze != null) {
	        String fileName = ze.getName();
	        File newFile = new File(outputFolder + File.separator + fileName);
	        if (ze.isDirectory()) {
	            newFile.mkdirs();
	        } else {
	            new File(newFile.getParent()).mkdirs();
	            fos = new FileOutputStream(newFile);
	            int len;
	            while ((len = zis.read(buffer)) > 0) fos.write(buffer, 0, len);
	            fos.close();
	        }
	        ze = zis.getNextEntry();
	    }
	    zis.closeEntry();
	    zis.close();
	}
	
	private void setKey(String myKey, String algorithm) throws Exception {
		key = myKey.getBytes(StandardCharsets.UTF_8);
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		key = md.digest(key);
		key = Arrays.copyOf(key, chunkSize);
		secretKeySpec = new SecretKeySpec(key, algorithm);
	}
	
	private void generateKey() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		KeyPair pair = generator.generateKeyPair();
		privateKey = pair.getPrivate();
		publicKey = pair.getPublic();
	}
	
	private byte[] aesEncryption(byte[] data, String password) throws Exception {
		setKey(password, "AES");
		cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		baos = new ByteArrayOutputStream();
		createChunkBytes(data, baos, cipher);
		Base64.Encoder encoder = Base64.getEncoder();
		offset = 0;
		return encoder.encode(baos.toByteArray());
	}
	
	private byte[] aesDecryption(byte[] data, String password) throws Exception {
		setKey(password, "AES");
		cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		Base64.Decoder decoder = Base64.getDecoder();
		return cipher.doFinal(decoder.decode(data));
	}
	
	private byte[] rsaEncryption(byte[] data) throws Exception {
		cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		baos = new ByteArrayOutputStream();
		ByteArrayInputStream bais = new ByteArrayInputStream(data);
		byte[] chunk = new byte[117];
		int length;
		while ((length = bais.read(chunk)) != -1) {
			byte[] encryptedChunk = cipher.doFinal(chunk, 0, length);
			baos.write(encryptedChunk);
		}
		Base64.Encoder encoder = Base64.getEncoder();
		return encoder.encode(baos.toByteArray());
	}
	
	private byte[] rsaDecryption(byte[] data) throws Exception {
		cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		Base64.Decoder decoder = Base64.getDecoder();
		return cipher.doFinal(decoder.decode(data));
	}
	
	private byte[] tripleDESEncryption(byte[] data, String password) throws Exception {
		setKey(password, "TripleDES");
		cipher = Cipher.getInstance("TripleDES/CBC/PKCS5PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		baos = new ByteArrayOutputStream();
		createChunkBytes(data, baos, cipher);
		Base64.Encoder encoder = Base64.getEncoder();
		offset = 0;
		return encoder.encode(baos.toByteArray());
	}
	
	private byte[] tripleDESDecryption(byte[] data, String password) throws Exception {
		setKey(password, "TripleDES");
		cipher = Cipher.getInstance("TripleDES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		Base64.Decoder decoder = Base64.getDecoder();
		return cipher.doFinal(decoder.decode(data));
	}
	
	private void createChunkBytes(byte[] data, ByteArrayOutputStream baos, Cipher cipher) throws Exception {
		while (offset < data.length) {
			int length = Math.min(chunkSize, data.length - offset);
			byte[] chunk = Arrays.copyOfRange(data, offset, offset + length);
			byte[] encryptedChunk = cipher.update(chunk);
			baos.write(encryptedChunk);
			offset += length;
		}
		byte[] finalChunk = cipher.doFinal();
		baos.write(finalChunk);
	}
	
	private void disableAll() {
		EnDecrypbtn.setDisable(true);
		tfPassword.setDisable(true);
		createPasswordbtn.setDisable(true);
	}
	
	private void passwordInputChange() {
		EnDecrypbtn.setDisable(!checkValidPassword(tfPassword.getText()));
	}
	
	private void enablePasswordInputs() {
		tfPassword.setDisable(false);
		createPasswordbtn.setDisable(false);
	}

	private boolean checkValidPassword(String pw) {
		return (!pw.isEmpty() && pw.matches(regex));
	}
	
	private String generateRandomPassword() {
		String PASSWORD_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@$!%|*?&+-"; 
		Random random = new Random();
		
		StringBuilder sb = new StringBuilder();
		
		sb.append(PASSWORD_CHARS.charAt(random.nextInt(52)));
		sb.append(PASSWORD_CHARS.charAt(random.nextInt(10) + 52));
		sb.append(PASSWORD_CHARS.charAt(random.nextInt(10) + 62));
		
		while (!Pattern.matches(regex, sb)) sb.append(PASSWORD_CHARS.charAt(random.nextInt(PASSWORD_CHARS.length())));
		return sb.toString();
	}
	
	private void alert(AlertType alertType, String context) {
		alert.setAlertType(alertType);
		alert.setContentText(context);
		alert.show();
	}
}
