module kleinprojekt {
    requires javafx.controls;
    requires javafx.fxml;
	requires javafx.base;
	requires javafx.graphics;
	requires org.apache.commons.codec;
	requires java.base;
	requires java.prefs;

    opens kleinprojekt to javafx.fxml;
    exports kleinprojekt;
}
