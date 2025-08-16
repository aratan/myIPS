# Mejoras

- Rendimiento
- Más protocolos
- Codigo más claro

## FILTROS -f 
### protocolo port 80 host ip and host ip  -o pcap


go run main.go -i 056F7919-93CF-42F6-A10C-992A94C355BD --model gemma3:4b -t 45s -f "icmp and host 192.168.1.20 and host 192.168.1.15"



 go run main.go -i 056F7919-93CF-42F6-A10C-992A94C355BD --model gemma3:4b -t 45s -f "icmp and host 192.168.1.20 and host 192.168.1.15"

go run main.go -i 056F7919-93CF-42F6-A10C-992A94C355BD -f "tcp port 80"

go run main.go -i 056F7919-93CF-42F6-A10C-992A94C355BD --model gemma3:4b -t 45s -f "tcp port 80"



go run main.go -i 056F7919-93CF-42F6-A10C-992A94C355BD --model llama3:4b -t 1m -b 1h -f "tcp" -o "sesion_http.pcap"

 go run main.go -i 056F7919-93CF-42F6-A10C-992A94C355BD -f "tcp port 80 and host 192.168.1.15"

056F7919-93CF-42F6-A10C-992A94C355BD

go run main.go -i <ID-INTERFAZ> -f "host 192.168.1.11 and host 8.8.8.8"



