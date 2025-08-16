🛡️ Capacidades del Software: Advanced IPS Sniffer con IA
Este software es un sistema avanzado de detección y prevención de intrusiones (IPS) con capacidades profesionales de análisis de tráfico de red, integración de inteligencia artificial y respuesta automatizada. Aquí te explico todo lo que puede hacer:

🔍 Análisis Profundo del Tráfico de Red
Sniffing en tiempo real de todas las interfaces de red
Soporte completo de protocolos:
TCP (HTTP, HTTPS, SSH, FTP, SMTP, RDP, etc.)
UDP (DNS, DHCP, SNMP, NTP, etc.)
ICMP (Ping floods, escaneos)
IGMP, SCTP, GRE, IPSec (AH/ESP)
Protocolos especializados (SMB, MSSQL, MySQL, etc.)
Detección de contenido:
Análisis de tráfico HTTP/HTTPS (muestra cabeceras y contenido)
Monitoreo de consultas DNS sospechosas
Detección de túneles ocultos (GRE, IPSec)

🤖 Inteligencia Artificial Integrada

Análisis predictivo usando modelos de lenguaje avanzados (Llama 3.2)
Detección de patrones complejos que los sistemas tradicionales no captan:
Escaneos de puertos sofisticados
Ataques de fuerza bruta en múltiples protocolos
Floods distribuidos (ICMP/UDP/TCP)
Técnicas de evasión avanzadas
Comportamientos anómalos de red
Toma de decisiones automatizada:
Bloqueo inmediato de amenazas críticas
Monitoreo inteligente de actividad sospechosa
Clasificación de riesgo (bajo, medio, alto, crítico)

⚡ Prevención de Intrusiones Automatizada
Bloqueo en tiempo real de IPs maliciosas mediante el firewall de Windows
Gestión inteligente de bloqueos:
Duración configurable de bloqueos (ej: 15 minutos a 24 horas)
Desbloqueo automático cuando expira el tiempo
Registro detallado de razones de bloqueo
Mecanismos de seguridad:
Prevención de escaneos de puertos masivos
Protección contra ataques DoS/Smurf
Detección de reconocimiento de red
Bloqueo de tráfico malicioso antes de que cause daño

📊 Monitoreo y Reportes Profesionales
Dashboard en tiempo real con estadísticas de tráfico
Reportes de seguridad periódicos:
Top 5 IPs más activas (filtrando bloqueadas)
Análisis de tendencias de tráfico
Resumen de amenazas detectadas
Métricas de rendimiento del sistema
Registro detallado en archivo de logs (sniffer_ips_advanced.log)
Visualización con colores para identificar rápidamente amenazas

🛠️ Características Técnicas Avanzadas
Procesamiento paralelo con gorutinas de Go (hasta 10 workers)
Análisis concurrente sin ralentizar la captura
Filtrado con BPF para enfoque en tráfico relevante
Guardado de capturas en formato .pcap para análisis forense
Interfaz CLI profesional con Cobra
Diagnóstico automático del estado del sistema
Gestión eficiente de recursos incluso en redes con alto tráfico

💼 Casos de Uso Prácticos
Protección de redes corporativas contra ataques externos
Detección de malware que comunica con C&C
Análisis forense tras un incidente de seguridad
Monitoreo de servidores críticos (web, base de datos, etc.)
Protección de redes domésticas avanzadas
Herramienta de aprendizaje para estudiantes de ciberseguridad
Sistema de alerta temprana para redes sensibles

⚠️ Requisitos y Limitaciones
Sistema operativo: Windows (usa netsh para firewall)
Requiere permisos de administrador para bloquear IPs
Necesita Ollama instalado (modelo Llama 3.2 recomendado)
Enfocado en IPv4 (soporte limitado para IPv6)
Recomendado para redes medianas (no para backbone de ISP)

💡 Ventaja Única
Este sistema va más allá de los firewalls tradicionales al combinar:

Análisis profundo de protocolos a nivel de paquete
Inteligencia artificial contextual para entender el tráfico
Respuesta automatizada con criterios de seguridad profesionales
Capacidad de aprender de los patrones de tráfico de tu red específica
Es ideal para entornos donde necesitas protección proactiva sin depender exclusivamente de firmas de amenazas conocidas, especialmente contra ataques avanzados y cero-day que evaden sistemas tradicionales.





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




