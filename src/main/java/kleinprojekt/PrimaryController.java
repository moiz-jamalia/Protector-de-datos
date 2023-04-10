package kleinprojekt;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
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
	private String regex = new Regex().regex4();
	private boolean encrypted = false;
	private boolean decrypted = false;
	private String inputFile = null;
	private List<File> files = null;
	private File file = null;
	private String[] ciphers = { "AES", "RSA", "Salt", "Salt and Pepper" };
	
	@FXML
	private AnchorPane MainPane;
	
	@FXML
	private Button EnDecrypbtn;
	
	@FXML
	private Button encryptbtn;
	
	@FXML
	private Button decryptbtn;
	
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
		decrypted = false;
		encrypted = true;
		FilesEncryptDecryptSurface.setText("File/s to encrypt");
		CbCipher.getItems().addAll(ciphers);
    }
	
	@FXML
	void decrypt(ActionEvent event) {
		encryptbtn.setStyle("-fx-background-color: #fae580; -fx-font-weight: normal;");
		encryptbtn.setUnderline(false);
		decryptbtn.setStyle("-fx-background-color: #ffd866; -fx-font-weight: bold;");
		decryptbtn.setUnderline(true);
		EnDecrypbtn.setText("Decrypt");
		FilesEncryptDecryptSurface.setText("File to decrypt");
		decrypted = true;
		encrypted = false;
	}

	@FXML
	void encrypt(ActionEvent event) {
		encryptbtn.setStyle("-fx-background-color: #ffd866; -fx-font-weight: bold;");
		encryptbtn.setUnderline(true);
		decryptbtn.setStyle("-fx-background-color: #fae580; -fx-font-weight: normal;");
		decryptbtn.setUnderline(false);
		EnDecrypbtn.setText("Encrypt");
		FilesEncryptDecryptSurface.setText("File/s to encrypt");
		decrypted = false;
		encrypted = true;
	}
	
	@FXML
	private void handleDragOver(DragEvent event) {
		if (event.getDragboard().hasFiles()) event.acceptTransferModes(TransferMode.ANY);
	}
	
	@FXML
	private void handleDrop(DragEvent event) {
		if (encrypted && !decrypted) {
			files = event.getDragboard().getFiles();
			if (files.isEmpty()) System.out.println("Error No Files fetched");
			else FilesEncryptDecryptSurface.setText("File/s to encrypt ✅");
		} else if (!encrypted && decrypted){
			List<String> validExtension = Arrays.asList("encrypted");
			file = null;
			System.out.println(event.getDragboard().getFiles().stream().map(f -> getExtension(f.getName())).collect(Collectors.toList()));
			if (event.getDragboard().getFiles().stream().map(f -> getExtension(f.getName())).collect(Collectors.toList()).toString() == "[encrypted]") {
				file = (File) event.getDragboard().getFiles();
				FilesEncryptDecryptSurface.setText("File to Decrypt ✅");
				System.out.println(file.getName());
			}
			else System.out.println("Error No File fetched");
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
		System.out.println("Pressed Label");
		FileChooser fChooser = new FileChooser();
		if (decrypted && !encrypted) {
			FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("ENCRYPTED File (*.encrypted)", "*.encrypted");
			fChooser.getExtensionFilters().add(extFilter);
			File selectedFile = fChooser.showOpenDialog(null);
			if (selectedFile == null) System.out.println("Error No File fetched");
			else FilesEncryptDecryptSurface.setText("File to Decrypt ✅");
		} else if (encrypted && !decrypted) {
			List<File> files = fChooser.showOpenMultipleDialog(null);
			if (files.isEmpty()) System.out.println("Error No File fetched");
			else FilesEncryptDecryptSurface.setText("File/s to encrypt ✅");
		}
	}
	
	private String getExtension(String fileName) {
		int i = fileName.lastIndexOf('.');
		if (i > 0 && i < fileName.length() -1) return fileName.substring(i + 1).toLowerCase();
		else return "";
	}
	
	private void disableAll() {
		EnDecrypbtn.setDisable(true);
		if (decrypted && !encrypted) EnDecrypbtn.setText("Decrypt");
		else EnDecrypbtn.setText("Encrypt");
	}
	
	private void disableDownload() {
		
	}
	
	private void fileUpload() {
		
	}
	
	private void enablePasswordInputs() {
		
	}
	
	private boolean isEmpty(String str) {
		if (str.trim().length() == 0) return true;
		else return false;
	}
	
	private void toggleNavItemDisabled() {
		
	}
	
	private void downloadFile() {
		
	}
}