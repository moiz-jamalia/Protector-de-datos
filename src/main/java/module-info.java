module kleinprojekt {
    requires javafx.controls;
    requires javafx.fxml;
	requires javafx.base;
	requires javafx.graphics;
	requires automaton;
	requires org.apache.commons.codec;
	requires java.base;

    opens kleinprojekt to javafx.fxml;
    exports kleinprojekt;
}
