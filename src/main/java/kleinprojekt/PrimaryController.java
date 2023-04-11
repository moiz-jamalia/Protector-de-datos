package kleinprojekt;

import java.io.File;
import java.util.List;

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
	private String regex = new Regex().regex4();
	private Alert alert;
	private String inputFile = null;
	private List<File> files = null;
	private String[] ciphers = { "AES", "RSA", "Salt", "Salt and Pepper" };
	
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
		CbCipher.getItems().addAll(ciphers);
		alert = new Alert(AlertType.NONE);
	}
	
	@FXML
	void decrypt(ActionEvent event) {
		encryptbtn.setStyle("-fx-background-color: #fae580; -fx-font-weight: normal;");
		encryptbtn.setUnderline(false);
		decryptbtn.setStyle("-fx-background-color: #ffd866; -fx-font-weight: bold;");
		decryptbtn.setUnderline(true);
		EnDecrypbtn.setText("Decrypt");
		FilesEncryptDecryptSurface.setText("File to decrypt");
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
				for (File f : files) System.out.println(f.getName());
				FilesEncryptDecryptSurface.setText("File/s to encrypt ✅");
			}
		} else if (activeTab.equals("decrypted")){
			files = event.getDragboard().getFiles();
			if (files.isEmpty()) {
				alert.setAlertType(AlertType.ERROR);
				alert.setContentText("No File fetched!");
				alert.show();
				//System.out.println("No File fetched!");
			}else if (files.size() != 1) {
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
			} else if (files.get(0).getName().indexOf(".encrypted") == -1) {
				alert.setAlertType(AlertType.WARNING);
				alert.setContentText("Please select an encrypted File");
				alert.show();
				//System.out.println("Please select an encrypted File");
				return;
			} else {
				for (File f : files) System.out.println(f.getName());
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
			}
			else if (files.get(0).length() > maxFileSize) {
				alert.setAlertType(AlertType.WARNING);
			}
			else FilesEncryptDecryptSurface.setText("File to Decrypt ✅");
		} else if (activeTab.equals("encrypted")) {
			files = fChooser.showOpenMultipleDialog(null);
			if (files.isEmpty()) {
				alert.setAlertType(AlertType.ERROR);
				alert.setContentText("No File fetched!");
				alert.show();
				//System.out.println("Error No File fetched!");
			}
			else {
				for (File f : files) System.out.println(f.getName());
				FilesEncryptDecryptSurface.setText("File/s to encrypt ✅");
			}
		}
	}
	
	private void disableAll() {
		EnDecrypbtn.setDisable(true);
		if (activeTab.equals("decrypted")) EnDecrypbtn.setText("Decrypt");
		else EnDecrypbtn.setText("Encrypt");
	}
	
	private void passwordInputChange() {
		String pwInput = tfPassword.getText();
		
	}
	
	private boolean checkValidPassword(String pw) {
		return (!isEmpty(pw) && pw.matches(regex));
	}
	
	private void generatePassword() {
		tfPassword.setText("");
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