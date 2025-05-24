- **analisador.exe**: Script pra analisar os tcp 
- **splitter.exe**: Script pra separar um pcap grande em um micro pcap de 5000 pacotes pra teste 

---

## Compilar

### Analisador de pacotes TCP
```bash
gcc -I"C:\npcap-sdk\Include" -L"C:\npcap-sdk\Lib" analisador.c -lwpcap -lws2_32 -o analisador.exe
```

```bash
.\analisador.exe .\5000.pcap
```

### Splitter de pacotes TCP
```bash
gcc -I"C:\npcap-sdk\Include" -L"C:\npcap-sdk\Lib" splitter.c -lwpcap -lws2_32 -o splitter.exe
```

```bash
.\splitter.exe .\202504090545.pcap 5000.pcap
```

---

### O que falta fazer do trab

- [ ] Estimar **RTT** (Round Trip Time)
- [ ] Calcular **throughput médio por conexão**
- [ ] Analisar a **evolução da janela de congestionamento**
- [ ] Detectar **fluxos elefantes** e **microbursts**
