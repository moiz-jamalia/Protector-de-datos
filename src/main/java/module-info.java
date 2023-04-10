module kleinprojekt {
    requires javafx.controls;
    requires javafx.fxml;
	requires javafx.base;
	requires javafx.graphics;

    opens kleinprojekt to javafx.fxml;
    exports kleinprojekt;
}
