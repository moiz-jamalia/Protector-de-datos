package kleinprojekt;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.time.Year;
import java.util.Arrays;
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
import javafx.stage.FileChooser;

public class PrimaryController {

	private String activeTab = "encrypt";
	private int maxFileSize = 2 * (1024 * 1024);
	private String regex = new Regex().getRegex4();
	private Alert alert;
	private List<File> files = null;
	private String[] ciphers = { "AES", "RSA", "Salt", "Salt and Pepper" };
	private byte[] key;
	private SecretKeySpec secretKeySpec;
	
	@FXML
	private AnchorPane MainPane;
	
	@FXML
	private Button EnDecrypbtn;
	
	@FXML
	private Button Downloadbtn;
	
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
		Downloadbtn.setVisible(false);
		EnDecrypbtn.setVisible(true);
		EnDecrypbtn.getStyleClass().add("btn-red");
		tfPassword.getStyleClass().add("txt-pw");
		CbCipher.getItems().addAll(ciphers);
		alert = new Alert(AlertType.NONE);
		//Xeger generate = new Xeger(regex);
		System.out.println("Regex: " + regex);
		CbCipher.getSelectionModel().selectedIndexProperty().addListener((args, oldVal, newVal) -> {
			try {
				crypt();
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
	private void handleDragOver(DragEvent event) {
		if (event.getDragboard().hasFiles()) event.acceptTransferModes(TransferMode.ANY);
	}
	
	@FXML
	private void handleDrop(DragEvent event) {
		if (activeTab.equals("encrypted")) {
			files = event.getDragboard().getFiles();
			if (files.isEmpty()) {
				alert.setAlertType(AlertType.ERROR);
				alert.setContentText("No Files fetched!");
				alert.show();
				//System.out.println("Error No Files fetched!");
				return;
			}
			else {
				//for (File f : files) System.out.println(f.getName());
				FilesEncryptDecryptSurface.setText("File/s to encrypt ✅");
			}
		} else if (activeTab.equals("decrypted")){
			files = event.getDragboard().getFiles();
			if (files.isEmpty()) {
				alert.setAlertType(AlertType.ERROR);
				alert.setContentText("No File fetched!");
				alert.show();
				//System.out.println("No File fetched!");
			}else if (files.get(0).getName().indexOf(".encrypted") == -1) {
				alert.setAlertType(AlertType.WARNING);
				alert.setContentText("Please select an encrypted File");
				alert.show();
				//System.out.println("Please select an encrypted File");
				return;
			} else if (files.get(0).length() > maxFileSize) {
				alert.setAlertType(AlertType.WARNING);
				alert.setContentText("Large file sizes might crash the application \nPlease select smaller files.");
				alert.show();
				//System.out.println("Large file sizes might crash the application \nPlease select smaller files.");
				return;
			} else if (files.size() != 1) {
				alert.setAlertType(AlertType.WARNING);
				alert.setContentText("Please select one File to decrypt!");
				alert.show();
				//System.out.println("Please select one File to decrypt!");
				return;
			} else {
				//for (File f : files) System.out.println(f.getName());
				FilesEncryptDecryptSurface.setText("File to Decrypt ✅");		
			}
		}
	}
	
	@FXML
	private void handleHover(MouseEvent event) {
		FilesEncryptDecryptSurface.setStyle("-fx-background-color: #f1bc31; -fx-text-fill: white;");
	}
	
	@FXML
	private void handleExited(MouseEvent event) {
		FilesEncryptDecryptSurface.setStyle("-fx-backgorund-color: transparent; -fx-text-fill: #f1bc31; -fx-border-color: #f1bc31;");
	}
	
	@FXML
	private void handlePressed(MouseEvent event) {
		FileChooser fChooser = new FileChooser();
		if (activeTab.equals("decrypted")) {
			FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("ENCRYPTED File (*.encrypted)", "*.encrypted");
			fChooser.getExtensionFilters().add(extFilter);
			files = fChooser.showOpenMultipleDialog(null);
			if (files.isEmpty()) {
				alert.setAlertType(AlertType.ERROR);
				alert.setContentText("No File fetched!");
				alert.show();
				return;
				//System.out.println("Error No File fetched!");
			} else if (files.size() != 1) {
				alert.setAlertType(AlertType.WARNING);
				alert.setContentText("Please select one File to decrypt!");
				alert.show();
				//System.out.println("Please select one File to decrypt!");
				return;
			} else if (files.get(0).length() > maxFileSize) {
				alert.setAlertType(AlertType.WARNING);
				alert.setContentText("Large file sizes might crash the application \nPlease select smaller files.");
				alert.show();
				//System.out.println("Large file sizes might crash the application \nPlease select smaller files.");
				return;
			} else {
				//for (File f : files) System.out.println(f.getName());
				FilesEncryptDecryptSurface.setText("File to Decrypt ✅");
			}
		} else if (activeTab.equals("encrypted")) {
			files = fChooser.showOpenMultipleDialog(null);
			if (files.isEmpty()) {
				alert.setAlertType(AlertType.ERROR);
				alert.setContentText("No File fetched!");
				alert.show();
				//System.out.println("Error No File fetched!");
			}
			else {
				//for (File f : files) System.out.println(f.getName());
				FilesEncryptDecryptSurface.setText("File/s to encrypt ✅");
			}
		}
	}
	
	 @FXML
	 private void generatePassword(ActionEvent event) {
		//Still in process
		 
		 
		//Xeger generator = new Xeger(regex);
		//tfPassword.setText(generator.generate());
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
	
	private void crypt() throws Exception {
		String password = tfPassword.getText().toString();
		File zipFile = null;
		FileOutputStream fos = null;
		FileInputStream fis = null;
		ZipOutputStream zos = null;
		BufferedInputStream bis = null;
		byte[] data = null;
		
		if (files == null) {
			if (activeTab.equals("encrypted")) {
				alert.setAlertType(AlertType.WARNING);
				alert.setContentText("Please select a file to encrypt!");
				alert.show();
				return;
			} else if (activeTab.equals("decrypted")) {
				alert.setAlertType(AlertType.WARNING);
				alert.setContentText("Please select a file to decrypt!");
				alert.show();
				return;
			}
		} else if (isEmpty(password)) {
			alert.setAlertType(AlertType.WARNING);
			alert.setContentText("Please enter a valid Password");
			alert.show();
		} else {
			if (activeTab.equals("encrypted")) {
				System.out.println("File size: " + files.size());
				if (files.size() > 1) {
					zipFile = new File("cryptedZipFile");
					fos = new FileOutputStream(zipFile);
					zos = new ZipOutputStream(fos);
					for (File f : files) zipFile(f, zos);	
					zos.close();
				} else {
					zipFile = new File(files.get(0).getName());
					fos = new FileOutputStream(zipFile);
					zos = new ZipOutputStream(fos);
					zipFile(zipFile, zos);
					zos.close();
				}
				fis = new FileInputStream(zipFile);
				data = new byte[(int) zipFile.length()];
				bis = new BufferedInputStream(fis);
				bis.read(data, 0, data.length);
			}
			String cipher = CbCipher.getSelectionModel().getSelectedItem();
			System.out.println("Cipher: " + CbCipher.getSelectionModel().getSelectedItem());
			switch (cipher) {
			case "AES":
				File file = AESEncrypt(data, tfPassword.getText());
				downloadFile(file);
				showDownloadButton();
				break;
				
			case "RSA":
				break;
				
			case "Salt":
				break;

			case "Salt and Pepper":
				break;
			}
			// encryption
		}
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
	
	private void setKey(final String myKey) throws Exception {
		key = myKey.getBytes("UTF-8");
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		key = md.digest(key);
		key = Arrays.copyOf(key, maxFileSize);
		secretKeySpec = new SecretKeySpec(key, "AES");
	}
	
	private File AESEncrypt(byte[] data, String secret) throws Exception {
		setKey(secret);
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		byte[] cipherText = cipher.doFinal(data);
		
		File file = new File(files.get(0).getName() + ".encrypted");
		
		return file;
	}

	private boolean checkValidPassword(String pw) {
		return (!isEmpty(pw) && pw.matches(regex));
	}
	
	private void disableDownload() {
		
	}
	
	private void showDownloadButton() {
		EnDecrypbtn.setVisible(false);
		Downloadbtn.setVisible(true);
	}
	
	private void fileUpload() {
		
	}
	
	private boolean isEmpty(String str) {
		if (str.trim().length() == 0) return true;
		else return false;
	}	
	
	private void toggleNavItemDisabled() {
		
	}
	
	private void downloadFile(File file) {
		
	}
}