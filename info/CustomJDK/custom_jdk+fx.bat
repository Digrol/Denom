

:: Add JavaFX modules into JDK

set PATH_TO_FX_MODS=.\javafx-jmods-19.0.2.1
set OUTDIR=.\jdk19+fx


.\jdk-19.0.2\bin\jlink --module-path %PATH_TO_FX_MODS% ^
    --add-modules java.se,javafx.fxml,javafx.web,javafx.media,javafx.swing ^
    --bind-services --output %OUTDIR%





::   --add-modules java.se,javafx.fxml,javafx.web,javafx.swing ^
