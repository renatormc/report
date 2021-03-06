from reader_server.reader_server import ReaderServer
import sys
from PyQt5.QtWidgets import QApplication, QStyleFactory
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt
# import qdarkstyle

app = QApplication(sys.argv)

app.setStyle(QStyleFactory.create("Fusion"));
defaultFont = QApplication.font();
defaultFont.setPointSize(defaultFont.pointSize()+2);
app.setFont(defaultFont);
darkPalette = QPalette();
darkPalette.setColor(QPalette.Window,QColor(53,53,53));
darkPalette.setColor(QPalette.WindowText,Qt.white);
darkPalette.setColor(QPalette.Disabled,QPalette.WindowText,QColor(127,127,127));
darkPalette.setColor(QPalette.Base,QColor(42,42,42));
darkPalette.setColor(QPalette.AlternateBase,QColor(66,66,66));
darkPalette.setColor(QPalette.ToolTipBase,Qt.white);
darkPalette.setColor(QPalette.ToolTipText,Qt.white);
darkPalette.setColor(QPalette.Text,Qt.white);
darkPalette.setColor(QPalette.Disabled,QPalette.Text,QColor(127,127,127));
darkPalette.setColor(QPalette.Dark,QColor(35,35,35));
darkPalette.setColor(QPalette.Shadow,QColor(20,20,20));
darkPalette.setColor(QPalette.Button,QColor(53,53,53));
darkPalette.setColor(QPalette.ButtonText,Qt.white);
darkPalette.setColor(QPalette.Disabled,QPalette.ButtonText,QColor(127,127,127));
darkPalette.setColor(QPalette.BrightText,Qt.red);
darkPalette.setColor(QPalette.Link,QColor(42,130,218));
darkPalette.setColor(QPalette.Highlight,QColor(42,130,218));
darkPalette.setColor(QPalette.Disabled,QPalette.Highlight,QColor(80,80,80));
darkPalette.setColor(QPalette.HighlightedText,Qt.white);
darkPalette.setColor(QPalette.Disabled,QPalette.HighlightedText,QColor(127,127,127));

app.setPalette(darkPalette);


w = ReaderServer()
w.show()
w.run()
sys.exit(app.exec_())