javac -classpath "..\bin" -d "..\bin" ..\src\ptmf2pcap\ByteUtils.java
javac -classpath "..\bin" -d "..\bin" ..\src\ptmf2pcap\Pcap.java
javac -classpath "..\bin" -d "..\bin" ..\src\ptmf2pcap\PtmfFrame.java
javac -classpath "..\bin" -d "..\bin" ..\src\ptmf2pcap\UserInterfacePtmfFrame.java
javac -classpath "..\bin" -d "..\bin" ..\src\ptmf2pcap\SipPtmfFrame.java
javac -classpath "..\bin" -d "..\bin" ..\src\ptmf2pcap\DiameterPtmfFrame.java
javac -classpath "..\bin" -d "..\bin" ..\src\ptmf2pcap\IpPtmfFrame.java
javac -classpath "..\bin" -d "..\bin" ..\src\ptmf2pcap\PtmfFile.java
javac -classpath "..\bin" -d "..\bin" ..\src\ptmf2pcap\Ui.java
javac -classpath "..\bin" -d "..\bin" ..\src\ptmf2pcap\Cli.java
javac -classpath "..\bin" -d "..\bin" ..\src\ptmf2pcap\Gui.java

jar cvfm ..\ptmf2pcap.jar Manifest.txt -C "..\bin" .

pause