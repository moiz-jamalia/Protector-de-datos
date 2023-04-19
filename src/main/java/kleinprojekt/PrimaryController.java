package kleinprojekt;

import java.io.BufferedInputStream;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.zip.ZipEntry;
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
import nl.flotsam.xeger.Xeger;


public class PrimaryController {

	private String activeTab = "encrypt";
	private int maxFileSize = 2 * (1024 * 1024);
	private String regex = new Regex().getRegex1();
	private Alert alert;
	private List<File> files = null;
	private String[] ciphers = { "AES", "RSA", "TripleDES" };
	private Cipher cipher = null;
	private byte[] encryptedFile;
	private byte[] decryptedFile;
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
		savebtn.setVisible(false);
		EnDecrypbtn.setVisible(true);
		EnDecrypbtn.getStyleClass().add("stripes");
		tfPassword.getStyleClass().add("txt-pw");
		CbCipher.getItems().addAll(ciphers);
		cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
		alert = new Alert(AlertType.NONE);
		System.out.println("Regex: " + regex); //debugging
		CbCipher.getSelectionModel().selectedIndexProperty().addListener((args, oldVal, newVal) -> {
			try {
				if (isEmpty(tfPassword.getText()) || files.size() >= 1 || (CbCipher.getSelectionModel().getSelectedIndex() < 0)) {
					System.out.println("Remove Style"); //debugging
					System.out.println("Get Selected Index: " + CbCipher.getSelectionModel().getSelectedIndex()); //debugging
					EnDecrypbtn.getStyleClass().remove("stripes");
					EnDecrypbtn.getStyleClass().add("btn-red");
				} else {
					System.out.println("Add Style"); //debugging
					System.out.println("Get Selected Index: " + CbCipher.getSelectionModel().getSelectedIndex()); //debugging
					EnDecrypbtn.getStyleClass().remove("btn-red");
					EnDecrypbtn.getStyleClass().add("stripes");
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		});
	}
	
	@FXML
	void decrypt(ActionEvent event) {
		encryptbtn.setStyle("-fx-background-color: #fae580; -fx-font-weight: normal;");
		encryptbtn.setUnderline(false);
		decryptbtn.setStyle("-fx-background-color: #ffd866; -fx-font-weight: bold;");
		decryptbtn.setUnderline(true);
		EnDecrypbtn.setText("Decrypt");
		FilesEncryptDecryptSurface.setText("File to decrypt");
		tfPassword.setPrefWidth(200);
		createPasswordbtn.setVisible(false);
		tfPassword.clear();
		activeTab = "decrypted";
	}

	@FXML
	void encrypt(ActionEvent event) {
		encryptbtn.setStyle("-fx-background-color: #ffd866; -fx-font-weight: bold;");
		encryptbtn.setUnderline(true);
		decryptbtn.setStyle("-fx-background-color: #fae580; -fx-font-weight: normal;");
		decryptbtn.setUnderline(false);
		EnDecrypbtn.setText("Encrypt");
		FilesEncryptDecryptSurface.setText("File/s to encrypt");
		tfPassword.setPrefWidth(165);
		createPasswordbtn.setVisible(true);
		tfPassword.clear();
		activeTab = "encrypted";
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
			else FilesEncryptDecryptSurface.setText("File/s to encrypt ✅");
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
			} else FilesEncryptDecryptSurface.setText("File to Decrypt ✅");		
		}
	}
	
	@FXML
	void handleHover(MouseEvent event) {
		FilesEncryptDecryptSurface.setStyle("-fx-background-color: #f1bc31; -fx-text-fill: white;");
	}
	
	@FXML
	void handleExited(MouseEvent event) {
		FilesEncryptDecryptSurface.setStyle("-fx-backgorund-color: transparent; -fx-text-fill: #f1bc31; -fx-border-color: #f1bc31;");
	}
	
	@FXML
	void mouseHover(MouseEvent event) {
		createPasswordbtn.setStyle("-fx-background-color: #f1bc31; -fx-text-fill: white;");
	}
	
	@FXML
	void mouseExit(MouseEvent event) {
		createPasswordbtn.setStyle("-fx-backgorund-color: transparent; -fx-text-fill: #f1bc31; -fx-border-color: #f1bc31;");
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
			} else FilesEncryptDecryptSurface.setText("File to Decrypt ✅");
		} else if (activeTab.equals("encrypted")) {
			files = fChooser.showOpenMultipleDialog(null);
			if (files.isEmpty()) {
				alert(AlertType.ERROR, "No File fetched!");
				return;
			}
			else FilesEncryptDecryptSurface.setText("File/s to encrypt ✅");
		}
	}
	
	@FXML
	void generatePassword(ActionEvent event) {
		//Still in process		 
		Xeger xeger = new Xeger(regex);
		tfPassword.setText(xeger.generate());
	 }
	
	@FXML
	void crypt(MouseEvent event) {
		if (isEmpty(tfPassword.getText()) || files.size() >= 1 || CbCipher.getSelectionModel().getSelectedIndex() < 0) {
			EnDecrypbtn.setVisible(false);
			savebtn.setVisible(true);	
		}
		else {
			EnDecrypbtn.setVisible(true);
			savebtn.setVisible(false);
		}
	}
	
    @FXML
    void saveClicked(MouseEvent event) throws Exception {
    	String password = tfPassword.getText();
		File zipFile = null;
		FileOutputStream fos = null;
		FileInputStream fis = null;
		ZipOutputStream zos = null;
		BufferedInputStream bis = null;
		byte[] data = null;
		DirectoryChooser dirChooser = new DirectoryChooser();
		File dirFile = dirChooser.showDialog(null);
		if (files == null) {
			if (activeTab.equals("encrypted")) {
				alert(AlertType.WARNING, "Please select a file to encrypt!");
				return;
			} else if (activeTab.equals("decrypted")) {
				alert(AlertType.WARNING, "Please select a file to decrypt!");
				return;
			}
		} else if (isEmpty(password)) {
			alert(AlertType.WARNING, "Please enter a valid Password");
			return;
		} else {
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
				
				String cipher = CbCipher.getSelectionModel().getSelectedItem();
				System.out.println("Pwd Valid: " + checkValidPassword(password));
				System.out.println("Cipher:" + cipher);
			
				if (checkValidPassword(password)) {
					switch (cipher) {
					case "AES":
						encryptedFile = AESEncrypt(data, password); 
						break;
					
					case "RSA":
						generateKey();
						encryptedFile = RSAEncrypt(data);
						break;
					
					case "TripleDES":
						encryptedFile = TripleDESEncrypt(data, password);
						break;
					}
				}
				
				String encryptedFileName = null;
				
				encryptedFileName = files.size() > 1 ? "cryptedZipFile.encrypted" : files.get(0).getName() + ".encrypted";
				
				try (FileOutputStream foss = new FileOutputStream(dirFile + "\\" + encryptedFileName)) {
					foss.write(encryptedFile);
				}
				
				if (zipFile.delete()) System.out.println("successful deleted");
				else System.out.println("fuck u brad!");
				
			} else if (activeTab.equals("decrypted")) {
				String cipher = CbCipher.getSelectionModel().getSelectedItem();
				
				if (checkValidPassword(password)) {
					switch (cipher) {
					case "AES":
						decryptedFile = AESDecrypt(data, password);
						break;
					
					case "RSA":
						decryptedFile = RSADecrypt(data);
						break;
					
					case "TripleDES":
						decryptedFile = TripleDESDecrypt(data, password);
						break;
					}
				}
				try (FileOutputStream foss = new FileOutputStream(dirFile + "\\" + files.get(0).getName())) {
					foss.write(decryptedFile);
				}
			}
			
		}
    }
	
	private void disableAll() {
		EnDecrypbtn.setDisable(true);
		if (activeTab.equals("decrypted")) EnDecrypbtn.setText("Decrypt");
		else EnDecrypbtn.setText("Encrypt");
	}
	
	private void passwordInputChange() {
		//Still in progress
		
		String pwInput = tfPassword.getText();
	}
	
	private void enablePasswordInputs() {
		tfPassword.setDisable(false);
		createPasswordbtn.setDisable(false);
	}
	
	private void zipFile(File file, ZipOutputStream zos) throws IOException {
		BufferedInputStream bis = null;
		try {
			FileInputStream fis = new FileInputStream(file);
			bis = new BufferedInputStream(fis, maxFileSize);
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
	
	private void setKey(final String myKey, String algorithm) throws Exception {
		key = myKey.getBytes(StandardCharsets.UTF_8);
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		key = md.digest(key);
		key = Arrays.copyOf(key, maxFileSize);
		secretKeySpec = new SecretKeySpec(key, algorithm);
	}
	
	private byte[] AESEncrypt(byte[] data, String passowrd) throws Exception {
		setKey(passowrd, "AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		Base64.Encoder encoder = Base64.getEncoder();
		return encoder.encode(cipher.doFinal(data));
	}
	
	private byte[] AESDecrypt(byte[] data, String password) throws Exception {
		setKey(password, "AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		Base64.Decoder decoder = Base64.getDecoder();
		return cipher.doFinal(decoder.decode(data));
	}
	
	private void generateKey() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(maxFileSize);
		KeyPair pair = generator.generateKeyPair();
		privateKey = pair.getPrivate();
		publicKey = pair.getPublic();
	}
	
	private byte[] RSAEncrypt(byte[] data) throws Exception {
		cipher = Cipher.getInstance("RSA/ECB/PKS1PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		Base64.Encoder encoder = Base64.getEncoder();
		return encoder.encode(cipher.doFinal(data));
	}
	
	private byte[] RSADecrypt(byte[] data) throws Exception {
		cipher = Cipher.getInstance("RSA/ECB/PKS1PADDING");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		Base64.Decoder decoder = Base64.getDecoder();
		return cipher.doFinal(decoder.decode(data));
	}
	
	private byte[] TripleDESEncrypt(byte[] data, String password) throws Exception {
		setKey(password, "TripleDES");
		cipher = Cipher.getInstance("TripleDES/CBC/PKCS5PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		Base64.Encoder encoder = Base64.getEncoder();
		return encoder.encode(cipher.doFinal(data));
	}
	
	private byte[] TripleDESDecrypt(byte[] data, String password) throws Exception {
		setKey(password, "TripleDES");
		cipher = Cipher.getInstance("TripleDES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		Base64.Decoder decoder = Base64.getDecoder();
		return cipher.doFinal(decoder.decode(data));
	}

	private boolean checkValidPassword(String pw) {
		return (!isEmpty(pw) && pw.matches(regex));
	}

	private boolean isEmpty(String str) {
		if (str.trim().length() == 0) return true;
		else return false;
	}	
	
	private void alert(AlertType alertType, String context) {
		alert.setAlertType(alertType);
		alert.setContentText(context);
		alert.show();
	}
}
