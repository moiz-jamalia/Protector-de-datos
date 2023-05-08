package kleinprojekt;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.prefs.Preferences;
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
	private final String aesAlgorithm = "AES/ECB/PKCS5PADDING";
	private final String blowfishAlgorithm = "Blowfish";
	private int maxFileSize = 2 * (1024 * 1024);
	private int chunkSize = 16;
	private int offset = 0;
	private ByteArrayOutputStream baos = null;
	private String regex = null;
	private Alert alert;
	private List<File> files = new ArrayList<File>();
	private String[] ciphers = { "AES", "Blowfish" };
	private String[] passwordComplexity = { "Easy", "Medium", "Immediate", "Hard" };
	private String[] pwInfo = new String[4];
	private Cipher cipher = null;
	private byte[] encryptedFile = null;
	private byte[] decryptedFile = null;
	private byte[] key;
	private SecretKeySpec secretKeySpec;
	private final String regex_key = new Regex().getRegex1();
	private Preferences prefs;
	
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
	private Button infobtn;
	
	@FXML
	private Button createPasswordbtn;
	
	@FXML
	private ComboBox<String> cbCipher;
	
	@FXML
	private ComboBox<String> cbPasswordComplex;
	
	@FXML
	private TextField tfPassword;
	
	@FXML
	private Label FilesEncryptDecryptSurface;
    
	@FXML
	void initialize() throws Exception {
		disableAll();
		encryptbtn.setStyle("-fx-background-color: #ffd866; -fx-font-weight: bold;");
		encryptbtn.setUnderline(true);
		activeTab = "encrypted";
		FilesEncryptDecryptSurface.setText("File/s to encrypt");
		createPasswordbtn.setText("🔑");
		savebtn.setVisible(false);
		EnDecrypbtn.setVisible(true);
		EnDecrypbtn.getStyleClass().add("stripes");
		tfPassword.getStyleClass().add("txt-pw");
		cbPasswordComplex.getItems().addAll(passwordComplexity);
		cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
		alert = new Alert(AlertType.NONE);
		prefs = Preferences.userRoot().node(getClass().getName());
		regex = prefs.get(regex_key, new Regex().getRegex1());
		cbCipher.getItems().addAll(ciphers);
		cbCipher.getSelectionModel().selectedIndexProperty().addListener((args, oldVal, newVal) -> {
			try {
				if (tfPassword.getText().isEmpty() || files.size() < 1 || cbCipher.getSelectionModel().isEmpty()) {
					EnDecrypbtn.getStyleClass().add("stripes");
					EnDecrypbtn.getStyleClass().remove("btn-red");
				} else {
					passwordInputChange();
					EnDecrypbtn.getStyleClass().add("btn-red");
					EnDecrypbtn.getStyleClass().remove("stripes");
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		});
	}
	
	@FXML
	void decrypt(ActionEvent event) throws Exception {
		disableAll();
		encryptbtn.setStyle("-fx-background-color: #fae580; -fx-font-weight: normal;");
		encryptbtn.setUnderline(false);
		decryptbtn.setStyle("-fx-background-color: #ffd866; -fx-font-weight: bold;");
		decryptbtn.setUnderline(true);
		EnDecrypbtn.setText("Decrypt");
		EnDecrypbtn.setVisible(true);
		savebtn.setVisible(false);
		FilesEncryptDecryptSurface.setText("File to decrypt");
		FilesEncryptDecryptSurface.setDisable(false);
		tfPassword.setPrefWidth(200);
		tfPassword.clear();
		createPasswordbtn.setVisible(false);
		activeTab = "decrypted";
		cbCipher.getSelectionModel().clearSelection();
		infobtn.setVisible(false);
		cbPasswordComplex.setVisible(false);
	}

	@FXML
	void encrypt(ActionEvent event) throws Exception {
		disableAll();
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
		cbCipher.getSelectionModel().clearSelection();
		infobtn.setVisible(true);
		cbPasswordComplex.setVisible(true);
		cbPasswordComplex.setDisable(false);
	}
	
	@FXML
	void pwInfo(ActionEvent event) throws Exception {
		if (pwInfo != null) alert(AlertType.INFORMATION, "INFORMATION", pwInfo[0], pwInfo[1]);
		else alert(AlertType.INFORMATION, "INFORMATION" , "No Complexity selected", "Please select a complexity for your password");
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
				alert(AlertType.ERROR, "ERROR", "No Files", "No Files fetched!");
				return;
			} else {
				enablePasswordInputs();
				FilesEncryptDecryptSurface.setText("File/s to encrypt ✅");
			}
		} else if (activeTab.equals("decrypted")){
			files = event.getDragboard().getFiles();
			if (files.isEmpty()) {
				alert(AlertType.ERROR, "ERROR", "No Files", "No File fetched!");
				return;
			} else if (files.get(0).getName().indexOf(".encrypted") == -1) {
				alert(AlertType.WARNING, "WARNING", "Wrong File selected", "Please select an encrypted File");
				return;
			} else if (files.get(0).length() > maxFileSize) {
				alert(AlertType.WARNING, "WARNING", "File is too big", "Large file sizes might crash the application \nPlease select smaller files.");
				return;
			} else if (files.size() != 1) {
				alert(AlertType.WARNING, "WARNING", "no File selected", "Please select one File to decrypt!");
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
				alert(AlertType.ERROR, "ERROR", "No Files", "No File fetched!");
				return;
			} else if (files.size() != 1) {
				alert(AlertType.WARNING, "WARNING", "No File selected", "Please select one File to decrypt!");
				return;
			} else if (files.get(0).length() > maxFileSize) {
				alert(AlertType.WARNING, "WARNING", "File is too big", "Large file sizes might crash the application \nPlease select smaller files.");
				return;
			} else {
				enablePasswordInputs();
				FilesEncryptDecryptSurface.setText("File to Decrypt ✅");
			}
		} else if (activeTab.equals("encrypted")) {
			files = fChooser.showOpenMultipleDialog(null);
			if (files.isEmpty()) {
				alert(AlertType.ERROR, "ERROR", "No Files", "No File fetched!");
				return;
			} else {
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
		if (tfPassword.getText().isEmpty() || files.size() < 1 || cbCipher.getSelectionModel().isEmpty() || cbPasswordComplex.getSelectionModel().isEmpty()) {
			EnDecrypbtn.setVisible(true);
			savebtn.setVisible(false);	
		} else {
			passwordInputChange();
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
				alert(AlertType.WARNING,"WARNING", "No File selected", "Please select a file to encrypt!");
				return;
			} else if (activeTab.equals("decrypted")) {
				alert(AlertType.WARNING, "WARNING", "No File selected", "Please select a file to decrypt!");
				return;
			}
		} else if (password.isEmpty()) {
			alert(AlertType.WARNING,"WARNING", "Password field is Empty", "Please enter a Password");
			return;
		} else if (!checkValidPassword(password)) {
			alert(AlertType.WARNING, "WARNING", "Invalid Password", "Password invalid please enter a Password");
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
				
				String cipher = cbCipher.getSelectionModel().getSelectedItem();
			
				if (checkValidPassword(password)) {
					switch (cipher) {
					case "AES":
						encryptedFile = aesEncryption(data, password);
						break;
					
					case "Blowfish":
						encryptedFile = blowfishEncryption(data, password);
						break;
					}
				}
				
				String encryptedFileName = files.size() > 1 ? "cryptedZipFile.zip.encrypted" : files.get(0).getName() + ".zip.encrypted";
				
				try (FileOutputStream foss = new FileOutputStream(dirFile + "\\" + encryptedFileName)) {
					foss.write(encryptedFile);
				}
				
				alert(AlertType.INFORMATION, "Information", "Encryption succeed", "File encrypted successfully");
				files = new ArrayList<File>();
				zipFile.delete();
				
				resetInputs();
								
			} else if (activeTab.equals("decrypted")) {
				if (files.size() != 1) {
					alert(AlertType.WARNING, "WARNING", "wrong File", "Please select a file to decrypt");
					return;
				}
				
				String encFileName = files.get(0).getName();
				if (!encFileName.endsWith(".encrypted")) {
					alert(AlertType.WARNING,"WARNING", "wrong File", "Please select a valid encrypted file!");
					return;
				}
				
				String decFileName = encFileName.substring(0, encFileName.length() - 10);
				File decFile = new File(dirFile, decFileName);
				if (decFile.exists()) {
					alert(AlertType.WARNING, "WARNING", "exact File", "File already exists! Please choose a different name.");
					return;
				}
				fis = new FileInputStream(files.get(0));
				byte[] encryptedData = fis.readAllBytes();
				String cipher = cbCipher.getSelectionModel().getSelectedItem();
				if (checkValidPassword(password)) {
					switch (cipher) {
					case "AES":
						decryptedFile = aesDecryption(encryptedData, password);
						break;
					
					case "Blowfish":
						decryptedFile = blowfishDecryption(encryptedData, password);
						break;
					}
				}
				fos = new FileOutputStream(decFile);
				fos.write(decryptedFile);
				fos.close();
				
				System.out.println(decFile); //debugging
				
				unzipFile(decFile, zis, dirFile);
				
				alert(AlertType.INFORMATION, "Information", "decryption succeed", "File decrypted successfully");
				files = new ArrayList<File>();
				
				resetInputs();
			}
		}
    }
    
    @FXML
    void chooseComplexityAction(ActionEvent event) {
    	if (cbPasswordComplex.getSelectionModel().getSelectedItem().equals("Easy")) {
    		regex = new Regex().getRegex1();
    		prefs.put(regex_key, regex);
    		pwInfo[0] = cbPasswordComplex.getSelectionModel().getSelectedItem();
    		pwInfo[1] = "Minimum eight characters\nat least one letter\none number and one special character";
    	} else if (cbPasswordComplex.getSelectionModel().getSelectedItem().equals("Medium")) {
			regex = new Regex().getRegex2();
			prefs.put(regex_key, regex);
			pwInfo[0] = cbPasswordComplex.getSelectionModel().getSelectedItem();
			pwInfo[1] = "Minimum eight characters\nat least one uppercase letter\none lowercase letter\none number and one special character";
		} else if (cbPasswordComplex.getSelectionModel().getSelectedItem().equals("Immediate")) {
			regex = new Regex().getRegex3();
			prefs.put(regex_key, regex);
			pwInfo[0] = cbPasswordComplex.getSelectionModel().getSelectedItem();
			pwInfo[1] = "Minimum twelve characters\nat least one uppercase letter\none lowercase letter\none number and one special character";
		} else if (cbPasswordComplex.getSelectionModel().getSelectedItem().equals("Hard")) {
			regex = new Regex().getRegex4();
			prefs.put(regex_key, regex);
			pwInfo[0] = cbPasswordComplex.getSelectionModel().getSelectedItem();
			pwInfo[1] = "Minimum 16 characters\nat least one uppercase letter\none lowercase letter\none number and one special character";
		} else {
			pwInfo = null;
			return;
		}
    	
    	if (activeTab.equals("encrypted")) {
    		FilesEncryptDecryptSurface.setDisable(false);
    		cbPasswordComplex.setDisable(true);
		} else {
			FilesEncryptDecryptSurface.setDisable(true);
			cbPasswordComplex.setDisable(false);
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
	
	@SuppressWarnings("resource")
	private void unzipFile(File zipFile, ZipInputStream zis, File outputFolder) throws IOException {
	    zis = new ZipInputStream(new FileInputStream(zipFile));
	    ZipEntry ze = zis.getNextEntry();
	    byte[] buffer = new byte[1024];
	    if (ze == null) {
	    	alert(AlertType.ERROR, "Error", "wrong Password or wrong decryption", "either the Password or the Decryption algorithm is Incorrect!");
	    	return;
		}
	    while (ze != null) {
	        String fileName = ze.getName();
	        File newFile = new File(outputFolder + File.separator + fileName);
	        if (ze.isDirectory()) {
	            newFile.mkdirs();
	        } else {
	            new File(newFile.getParent()).mkdirs();
	            FileOutputStream fos = new FileOutputStream(newFile);
	            try {
	                int len;
	                while ((len = zis.read(buffer)) > 0) fos.write(buffer, 0, len);
	            } finally {
	                fos.close();
	            }
	        }
	        ze = zis.getNextEntry();
	    }
	    zis.closeEntry();
	    zis.close();
	    zipFile.delete();
	}
	
	private void setKey(String myKey, String algorithm) throws Exception {
		key = myKey.getBytes(StandardCharsets.UTF_8);
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		key = md.digest(key);
		key = Arrays.copyOf(key, chunkSize);
		secretKeySpec = new SecretKeySpec(key, algorithm);
	}
	
	private byte[] aesEncryption(byte[] data, String password) throws Exception {
		setKey(password, "AES");
		cipher = Cipher.getInstance(aesAlgorithm);
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		baos = new ByteArrayOutputStream();
		createChunkBytes(data, baos, cipher);
		Base64.Encoder encoder = Base64.getEncoder();
		offset = 0;
		return encoder.encode(baos.toByteArray());
	}
	
	private byte[] aesDecryption(byte[] data, String password) throws Exception {
		setKey(password, "AES");
		cipher = Cipher.getInstance(aesAlgorithm);
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		byte[] encryptedBytes = Base64.getDecoder().decode(data);
		baos = new ByteArrayOutputStream();
		createChunkBytes(encryptedBytes, baos, cipher);
		offset = 0;
		return baos.toByteArray();
	}
	
	private byte[] blowfishEncryption(byte[] data, String password) throws Exception {
		setKey(password, blowfishAlgorithm);
		cipher = Cipher.getInstance(blowfishAlgorithm);
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		baos = new ByteArrayOutputStream();
		createChunkBytes(data, baos, cipher);
		Base64.Encoder encoder = Base64.getEncoder();
		offset = 0;
		return encoder.encode(baos.toByteArray());
	}
	
	private byte[] blowfishDecryption(byte[] data, String password) throws Exception {
		setKey(password, blowfishAlgorithm);
		cipher = Cipher.getInstance(blowfishAlgorithm);
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		byte[] decryptedBytes = Base64.getDecoder().decode(data);
		baos = new ByteArrayOutputStream();
		createChunkBytes(decryptedBytes, baos, cipher);
		offset = 0;
		return baos.toByteArray();
	}
	
	private void createChunkBytes(byte[] data, ByteArrayOutputStream baos, Cipher cipher) throws Exception {
		while (offset < data.length) {
			int length = Math.min(chunkSize, data.length - offset);
			byte[] chunk = Arrays.copyOfRange(data, offset, offset + length);
			byte[] cryptedChunk = cipher.update(chunk);
			baos.write(cryptedChunk);
			offset += length;
		}
		
		byte[] finalChunk = null;
		try {
			finalChunk = cipher.doFinal();	
		} catch (Exception e) {
			alert(AlertType.ERROR, "wrong Password", "Password is Wrong", "Your Password is invalid");
			return;
		}
		
		baos.write(finalChunk);
	}
	
	private void disableAll() {
		EnDecrypbtn.setDisable(true);
		tfPassword.setDisable(true);
		createPasswordbtn.setDisable(true);
		FilesEncryptDecryptSurface.setDisable(true);
	}
	
	private void passwordInputChange() {
		EnDecrypbtn.setDisable(!checkValidPassword(tfPassword.getText()));
	}
	
	private void enablePasswordInputs() {
		tfPassword.setDisable(false);
		createPasswordbtn.setDisable(false);
	}
	
	private void resetInputs() {
		EnDecrypbtn.setVisible(true);
		savebtn.setVisible(false);
		EnDecrypbtn.setDisable(true);
		tfPassword.clear();
		cbCipher.getSelectionModel().clearSelection();
		if (activeTab.equals("encrypted")) {
			cbPasswordComplex.setDisable(false);
			cbPasswordComplex.getSelectionModel().clearSelection();
			FilesEncryptDecryptSurface.setText("File/s to encrypt");
			files = new ArrayList<File>();
		} else {
			FilesEncryptDecryptSurface.setText("File/s to decrypt");
			files = new ArrayList<File>();
			cbPasswordComplex.setDisable(true);
		}
	}

	private boolean checkValidPassword(String pw) {
		return (!pw.isEmpty() && pw.matches(regex));
	}
	
	private String generateRandomPassword() {
		String passwordChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@$!%|*?&+-"; 
		Random random = new Random();
		
		StringBuilder sb = new StringBuilder();
		
		sb.append(passwordChars.charAt(random.nextInt(52)));
		sb.append(passwordChars.charAt(random.nextInt(10) + 52));
		sb.append(passwordChars.charAt(random.nextInt(10) + 62));
		
		while (!Pattern.matches(regex, sb)) sb.append(passwordChars.charAt(random.nextInt(passwordChars.length())));
		return sb.toString();	
	}
	
	private void alert(AlertType alertType, String title, String headerTitle, String context) {
		alert.setAlertType(alertType);
		alert.setTitle(title);
		alert.setHeaderText(headerTitle);
		alert.setContentText(context);
		alert.show();
	}
}
