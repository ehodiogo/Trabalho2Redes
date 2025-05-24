gcc -I"C:\npcap-sdk\Include" -L"C:\npcap-sdk\Lib" analisador.c -lwpcap -lws2_32 -o analisador.exe
.\analisador.exe .\5000.pcap

gcc -I"C:\npcap-sdk\Include" -L"C:\npcap-sdk\Lib" splitter.c -lwpcap -lws2_32 -o splitter.exe
.\splitter.exe .\202504090545.pcap 5000.pcap
