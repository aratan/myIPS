// Sniffer IPS completo con todos los protocolos y análisis concurrente con Ollama
// Versión mejorada con gorutinas para análisis paralelo y detección de protocolos completa
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
)

// --- Constantes para colores en la consola ---
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorBlue    = "\033[34m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorMagenta = "\033[35m"
	colorPurple  = "\033[95m"
	colorOrange  = "\033[38;5;208m"
	colorPink    = "\033[38;5;200m"
)

// --- Estructuras para la comunicación con Ollama ---
type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Format string `json:"format"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

type AnalysisResult struct {
	Action   string `json:"action"`
	IP       string `json:"ip"`
	Protocol string `json:"protocol"`
	Threat   string `json:"threat"`
	Reason   string `json:"reason"`
	Risk     string `json:"risk"`
}

type BlockedIP struct {
	Expiry time.Time
	Reason string
}

type StateManager struct {
	mu         sync.Mutex
	blockedIPs map[string]BlockedIP
}

type AnalysisJob struct {
	Summary   map[string]int
	Timestamp time.Time
}

// --- Variables Globales ---
var (
	packetSummary   = make(map[string]int)
	protocolCounter = make(map[string]int)
	summaryMutex    sync.Mutex
	stateManager    = &StateManager{
		blockedIPs: make(map[string]BlockedIP),
	}
	localIPs      map[string]bool
	analysisQueue = make(chan AnalysisJob, 100)
	workerPool    = 5 // Número de gorutinas trabajadoras
)

// --- Funciones de Utilidad ---

// listInterfaces muestra todas las interfaces de red disponibles
func listInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error al buscar dispositivos: %v", err)
	}

	fmt.Println("🔍 Interfaces de red disponibles:")
	for i, device := range devices {
		fmt.Printf("\n[%d] %s\n", i, device.Description)
		guid := strings.TrimPrefix(device.Name, "\\Device\\NPF_")
		fmt.Printf("    ID: %s\n", guid)
		for _, address := range device.Addresses {
			fmt.Printf("    IP: %s\n", address.IP)
		}
	}
}

// getLocalIPs obtiene las IPs locales para análisis de tráfico
func getLocalIPs() (map[string]bool, error) {
	ips := make(map[string]bool)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		ip = ip.To4()
		if ip == nil {
			continue // Ignorar IPv6
		}
		ips[ip.String()] = true
	}
	return ips, nil
}

// --- Función Principal ---
func main() {
	logFile, err := os.OpenFile("sniffer_ips_advanced.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("No se pudo abrir archivo de log: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	var (
		interfaceID          string
		filter               string
		outputFile           string
		ollamaModel          string
		ollamaURL            string
		analysisInterval     time.Duration
		blockDuration        time.Duration
		shouldListInterfaces bool
		workers              int
	)

	var rootCmd = &cobra.Command{
		Use:   "advanced-sniffer-ips",
		Short: "Sniffer IPS avanzado con análisis completo de protocolos y IA concurrente",
		Run: func(cmd *cobra.Command, args []string) {
			if shouldListInterfaces {
				listInterfaces()
				return
			}

			if interfaceID == "" {
				log.Fatal("❌ Error: Especifica el ID de interfaz con -i. Usa -l para ver interfaces.")
			}

			workerPool = workers
			var initErr error
			localIPs, initErr = getLocalIPs()
			if initErr != nil {
				log.Fatalf("❌ Error obteniendo IPs locales: %v", initErr)
			}

			logPrintln(colorGreen, fmt.Sprintf("🌐 IPs locales detectadas: %v", getIPList(localIPs)))
			logPrintln(colorCyan, fmt.Sprintf("🤖 Iniciando %d workers de análisis con Ollama", workerPool))

			runAdvancedSniffer(interfaceID, filter, outputFile, ollamaModel, ollamaURL, analysisInterval, blockDuration)
		},
	}

	rootCmd.Flags().StringVarP(&interfaceID, "interface", "i", "", "ID de interfaz de red")
	rootCmd.Flags().BoolVarP(&shouldListInterfaces, "list-interfaces", "l", false, "Lista interfaces disponibles")
	rootCmd.Flags().StringVarP(&filter, "filter", "f", "ip", "Filtro BPF")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Archivo .pcap de salida")
	rootCmd.Flags().StringVar(&ollamaModel, "model", "llama3.2", "Modelo Ollama")
	rootCmd.Flags().StringVar(&ollamaURL, "url", "http://localhost:11434/api/generate", "URL API Ollama")
	rootCmd.Flags().DurationVarP(&analysisInterval, "interval", "t", 30*time.Second, "Intervalo de análisis")
	rootCmd.Flags().DurationVarP(&blockDuration, "block-duration", "b", 15*time.Minute, "Duración de bloqueo")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 5, "Número de workers de análisis")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getIPList(ips map[string]bool) []string {
	list := make([]string, 0, len(ips))
	for ip := range ips {
		list = append(list, ip)
	}
	return list
}

// --- Lógica Principal del Sniffer Avanzado ---

func runAdvancedSniffer(interfaceID, filter, output, ollamaModel, ollamaURL string, interval, blockTime time.Duration) {
	device := "\\Device\\NPF_{" + interfaceID + "}"
	handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("❌ Error abriendo adaptador %s: %v", device, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("❌ Error aplicando filtro '%s': %v", filter, err)
	}

	logPrintln(colorGreen, fmt.Sprintf("🚀 Captura iniciada en %s | Filtro: '%s' | Modelo: '%s'", interfaceID, filter, ollamaModel))

	var pcapWriter *pcapgo.Writer
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			log.Fatalf("❌ Error creando archivo %s: %v", output, err)
		}
		defer f.Close()
		pcapWriter = pcapgo.NewWriter(f)
		pcapWriter.WriteFileHeader(65535, layers.LinkTypeEthernet)
		logPrintln(colorCyan, fmt.Sprintf("💾 Guardando en: %s", output))
	}

	// Iniciar workers de análisis
	startAnalysisWorkers(ollamaModel, ollamaURL, blockTime)

	// Iniciar scheduler de análisis
	go analysisScheduler(interval)

	// Iniciar gestor de desbloqueos
	go stateManager.manageUnblocks()

	// Mostrar estadísticas cada minuto
	go showStats()

	// Procesar paquetes
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if pcapWriter != nil {
			pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
		processAdvancedPacket(packet)
	}
}

// --- Procesamiento Avanzado de Paquetes ---

func processAdvancedPacket(packet gopacket.Packet) {
	var srcIP, dstIP, logEntry, logColor, protocol string
	var directionTag string
	var port uint16

	// Análisis de capa IP
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	srcIP = ip.SrcIP.String()
	dstIP = ip.DstIP.String()

	// Determinar dirección del tráfico
	if localIPs[srcIP] {
		directionTag = "[OUT]"
		logColor = colorBlue
	} else if localIPs[dstIP] {
		directionTag = "[IN] "
		logColor = colorRed
	} else {
		directionTag = "[FWD]"
		logColor = colorYellow
	}

	// Análisis por protocolo
	switch ip.Protocol {
	case layers.IPProtocolTCP:
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		port = uint16(tcp.DstPort)
		protocol = identifyTCPProtocol(tcp)
		logEntry = fmt.Sprintf("%s [TCP/%s] %s:%d → %s:%d", directionTag, protocol, srcIP, tcp.SrcPort, dstIP, tcp.DstPort)

		if directionTag == "[IN] " {
			updateTrafficStats("TCP", protocol, srcIP, port)
		}

		analyzeHTTPSContent(packet, tcp, directionTag)

	case layers.IPProtocolUDP:
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		port = uint16(udp.DstPort)
		protocol = identifyUDPProtocol(udp)
		logEntry = fmt.Sprintf("%s [UDP/%s] %s:%d → %s:%d", directionTag, protocol, srcIP, udp.SrcPort, dstIP, udp.DstPort)

		if directionTag == "[IN] " {
			updateTrafficStats("UDP", protocol, srcIP, port)
		}

		analyzeDNSContent(packet, udp, directionTag)

	case layers.IPProtocolICMPv4:
		icmp := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		protocol = identifyICMPType(icmp)
		logEntry = fmt.Sprintf("%s [ICMP/%s] %s → %s", directionTag, protocol, srcIP, dstIP)
		logColor = colorMagenta

		if directionTag == "[IN] " {
			updateTrafficStats("ICMP", protocol, srcIP, 0)
		}

	case layers.IPProtocolIGMP:
		protocol = "IGMP"
		logEntry = fmt.Sprintf("%s [IGMP] %s → %s", directionTag, srcIP, dstIP)
		logColor = colorPink

		if directionTag == "[IN] " {
			updateTrafficStats("IGMP", "MULTICAST", srcIP, 0)
		}

	case layers.IPProtocolSCTP:
		protocol = "SCTP"
		logEntry = fmt.Sprintf("%s [SCTP] %s → %s", directionTag, srcIP, dstIP)
		logColor = colorOrange

		if directionTag == "[IN] " {
			updateTrafficStats("SCTP", "STREAM", srcIP, 0)
		}

	case layers.IPProtocolIPv6HopByHop, layers.IPProtocolIPv6Routing, layers.IPProtocolIPv6Fragment, layers.IPProtocolICMPv6:
		protocol = "IPv6"
		logEntry = fmt.Sprintf("%s [IPv6] %s → %s", directionTag, srcIP, dstIP)
		logColor = colorCyan

	case layers.IPProtocolGRE:
		protocol = "GRE"
		logEntry = fmt.Sprintf("%s [GRE/TUNNEL] %s → %s", directionTag, srcIP, dstIP)
		logColor = colorPurple

		if directionTag == "[IN] " {
			updateTrafficStats("GRE", "TUNNEL", srcIP, 0)
		}

	case layers.IPProtocolAH:
		protocol = "AH"
		logEntry = fmt.Sprintf("%s [IPSec/AH] %s → %s", directionTag, srcIP, dstIP)
		logColor = colorGreen

		if directionTag == "[IN] " {
			updateTrafficStats("IPSEC", "AH", srcIP, 0)
		}

	case layers.IPProtocolESP:
		protocol = "ESP"
		logEntry = fmt.Sprintf("%s [IPSec/ESP] %s → %s", directionTag, srcIP, dstIP)
		logColor = colorGreen

		if directionTag == "[IN] " {
			updateTrafficStats("IPSEC", "ESP", srcIP, 0)
		}

	default:
		protocol = fmt.Sprintf("PROTO_%d", ip.Protocol)
		logEntry = fmt.Sprintf("%s [%s] %s → %s", directionTag, protocol, srcIP, dstIP)
		logColor = colorYellow

		if directionTag == "[IN] " {
			updateTrafficStats("OTHER", protocol, srcIP, 0)
		}
	}

	fmt.Println(logColor + logEntry + colorReset)
}

// --- Identificadores de Protocolos ---

func identifyTCPProtocol(tcp *layers.TCP) string {
	port := tcp.DstPort
	switch port {
	case 20, 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "TELNET"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 443:
		return "HTTPS"
	case 993:
		return "IMAPS"
	case 995:
		return "POP3S"
	case 3389:
		return "RDP"
	case 5432:
		return "POSTGRESQL"
	case 3306:
		return "MYSQL"
	case 1433:
		return "MSSQL"
	case 135:
		return "RPC"
	case 139, 445:
		return "SMB"
	case 1723:
		return "PPTP"
	default:
		return fmt.Sprintf("PORT_%d", port)
	}
}

func identifyUDPProtocol(udp *layers.UDP) string {
	port := udp.DstPort
	switch port {
	case 53:
		return "DNS"
	case 67, 68:
		return "DHCP"
	case 69:
		return "TFTP"
	case 123:
		return "NTP"
	case 161, 162:
		return "SNMP"
	case 514:
		return "SYSLOG"
	case 1701:
		return "L2TP"
	case 1812, 1813:
		return "RADIUS"
	case 4500:
		return "IPSEC_NAT"
	case 500:
		return "ISAKMP"
	default:
		return fmt.Sprintf("PORT_%d", port)
	}
}

func identifyICMPType(icmp *layers.ICMPv4) string {
	switch icmp.TypeCode.Type() {
	case layers.ICMPv4TypeEchoReply:
		return "PING_REPLY"
	case layers.ICMPv4TypeDestinationUnreachable:
		return "DEST_UNREACH"
	case layers.ICMPv4TypeRedirect:
		return "REDIRECT"
	case layers.ICMPv4TypeEchoRequest:
		return "PING_REQUEST"
	case layers.ICMPv4TypeTimeExceeded:
		return "TIME_EXCEEDED"
	default:
		return fmt.Sprintf("TYPE_%d", icmp.TypeCode.Type())
	}
}

// --- Análisis de Contenido ---

func analyzeHTTPSContent(packet gopacket.Packet, tcp *layers.TCP, direction string) {
	if tcp.DstPort == 80 || tcp.SrcPort == 80 || tcp.DstPort == 443 || tcp.SrcPort == 443 {
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload := appLayer.Payload()
			if len(payload) > 0 {
				if tcp.DstPort == 443 || tcp.SrcPort == 443 {
					logPrintln(colorPurple, fmt.Sprintf("    %s [HTTPS/TLS] Tráfico cifrado detectado (%d bytes)", direction, len(payload)))
				} else {
					content := string(payload[:min(200, len(payload))])
					logPrintln(colorPurple, fmt.Sprintf("    %s [HTTP] %s", direction, content))
				}
			}
		}
	}
}

func analyzeDNSContent(packet gopacket.Packet, udp *layers.UDP, direction string) {
	if udp.DstPort == 53 || udp.SrcPort == 53 {
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			if len(dns.Questions) > 0 {
				logPrintln(colorCyan, fmt.Sprintf("    %s [DNS] Query: %s", direction, string(dns.Questions[0].Name)))
			}
			if len(dns.Answers) > 0 {
				logPrintln(colorCyan, fmt.Sprintf("    %s [DNS] Answers: %d", direction, len(dns.Answers)))
			}
		}
	}
}

// --- Gestión de Estadísticas ---

func updateTrafficStats(baseProtocol, subProtocol, srcIP string, port uint16) {
	summaryMutex.Lock()
	defer summaryMutex.Unlock()

	key := fmt.Sprintf("%s_%s_FROM_%s", baseProtocol, subProtocol, srcIP)
	packetSummary[key]++

	protocolKey := fmt.Sprintf("%s/%s", baseProtocol, subProtocol)
	protocolCounter[protocolKey]++

	if port > 0 {
		portKey := fmt.Sprintf("PORT_%d_SCAN_FROM_%s", port, srcIP)
		packetSummary[portKey]++
	}
}

func showStats() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		summaryMutex.Lock()
		if len(protocolCounter) > 0 {
			logPrintln(colorGreen, "📊 Estadísticas de protocolos (último minuto):")
			for proto, count := range protocolCounter {
				fmt.Printf("   %s: %d paquetes\n", proto, count)
			}
			protocolCounter = make(map[string]int) // Reset
		}
		summaryMutex.Unlock()
	}
}

// --- Workers de Análisis Concurrente ---

func startAnalysisWorkers(model, url string, blockTime time.Duration) {
	for i := 0; i < workerPool; i++ {
		go analysisWorker(i, model, url, blockTime)
	}
	logPrintln(colorCyan, fmt.Sprintf("🤖 %d workers de análisis iniciados", workerPool))
}

func analysisWorker(id int, model, url string, blockTime time.Duration) {
	for job := range analysisQueue {
		logPrintln(colorYellow, fmt.Sprintf("👨‍💻 Worker %d procesando análisis...", id))

		prompt := buildAdvancedPrompt(job.Summary, job.Timestamp)
		result := sendToOllamaAsync(prompt, model, url)

		if result != nil {
			processAnalysisResult(*result, blockTime, id)
		}
	}
}

func analysisScheduler(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		summaryMutex.Lock()
		if len(packetSummary) == 0 {
			summaryMutex.Unlock()
			continue
		}

		currentSummary := make(map[string]int)
		for k, v := range packetSummary {
			currentSummary[k] = v
		}
		packetSummary = make(map[string]int)
		summaryMutex.Unlock()

		job := AnalysisJob{
			Summary:   currentSummary,
			Timestamp: time.Now(),
		}

		select {
		case analysisQueue <- job:
			logPrintln(colorCyan, fmt.Sprintf("📋 Trabajo de análisis enviado a cola (%d eventos)", len(currentSummary)))
		default:
			logPrintln(colorRed, "⚠️ Cola de análisis llena, descartando trabajo")
		}
	}
}

// --- Comunicación Avanzada con Ollama ---

func buildAdvancedPrompt(summary map[string]int, timestamp time.Time) string {
	var summaryLines []string
	var suspiciousPatterns []string

	for key, count := range summary {
		summaryLines = append(summaryLines, fmt.Sprintf("- %s: %d eventos", key, count))

		// Detectar patrones sospechosos
		if strings.Contains(key, "PORT_") && count > 10 {
			suspiciousPatterns = append(suspiciousPatterns, fmt.Sprintf("Posible escaneo de puertos: %s", key))
		}
		if strings.Contains(key, "ICMP_") && count > 50 {
			suspiciousPatterns = append(suspiciousPatterns, fmt.Sprintf("Posible ping flood: %s", key))
		}
		if strings.Contains(key, "TCP_") && count > 100 {
			suspiciousPatterns = append(suspiciousPatterns, fmt.Sprintf("Alto volumen TCP: %s", key))
		}
	}

	patterns := "Ningún patrón sospechoso detectado automáticamente."
	if len(suspiciousPatterns) > 0 {
		patterns = strings.Join(suspiciousPatterns, "\n")
	}

	return fmt.Sprintf(`Eres un experto analista de ciberseguridad especializado en detección de intrusiones y análisis de amenazas avanzadas.

CONTEXTO:
- Timestamp: %s
- Analizando tráfico de red ENTRANTE de los últimos %d segundos
- Sistema IPS activo con capacidad de bloqueo automático

DATOS DE TRÁFICO:
%s

PATRONES PRE-IDENTIFICADOS:
%s

INSTRUCCIONES:
Analiza el tráfico buscando:
1. Escaneos de puertos (múltiples TCP_PORT_X desde misma IP)
2. Ataques de fuerza bruta (múltiples intentos SSH/FTP/RDP)
3. Floods ICMP/UDP (alto volumen desde una IP)
4. Túneles sospechosos (GRE/VPN inusuales)
5. Tráfico IPSec anómalo
6. Patrones de reconocimiento
7. Intentos de evasión
8. Problemas de red

RESPUESTA:
Responde ÚNICAMENTE con JSON válido:
{
 "action": "block|monitor|allow",
 "ip": "IP_SOSPECHOSA",
 "protocol": "PROTOCOLO_AFECTADO", 
 "threat": "TIPO_AMENAZA",
 "reason": "DESCRIPCIÓN_TÉCNICA",
 "risk": "low|medium|high|critical"
}

Criterios de bloqueo:
- "block": Amenaza clara confirmada
- "monitor": Actividad sospechosa pero no concluyente  
- "allow": Tráfico normal

Analiza ahora:`,
		timestamp.Format("2006-01-02 15:04:05"),
		30,
		strings.Join(summaryLines, "\n"),
		patterns)
}

func sendToOllamaAsync(prompt, model, url string) *AnalysisResult {
	requestData := OllamaRequest{
		Model:  model,
		Prompt: prompt,
		Format: "json",
		Stream: false,
	}

	jsonData, _ := json.Marshal(requestData)
	client := &http.Client{Timeout: 45 * time.Second}

	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		logPrintln(colorRed, fmt.Sprintf("❌ Error conectando con Ollama: %v", err))
		return nil
	}
	defer resp.Body.Close()

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		logPrintln(colorRed, fmt.Sprintf("❌ Error decodificando respuesta Ollama: %v", err))
		return nil
	}

	var analysis AnalysisResult
	if err := json.Unmarshal([]byte(ollamaResp.Response), &analysis); err != nil {
		logPrintln(colorRed, fmt.Sprintf("❌ Error parseando JSON análisis: %v", err))
		logPrintln(colorRed, fmt.Sprintf("Respuesta recibida: %s", ollamaResp.Response))
		return nil
	}

	return &analysis
}

// logPrintln is a helper function to print colored logs to console and file
func logPrintln(color, message string) {
	log.Println(strings.TrimSuffix(message, colorReset)) // Log to file without color codes
	fmt.Println(color + message + colorReset)            // Print to console with color codes
}

func processAnalysisResult(result AnalysisResult, blockTime time.Duration, workerID int) {
	logPrintln(colorYellow, fmt.Sprintf("🧠 Worker %d - Análisis completado:", workerID))
	logPrintln(colorYellow, fmt.Sprintf("   Acción: %s | IP: %s | Protocolo: %s", result.Action, result.IP, result.Protocol))
	logPrintln(colorYellow, fmt.Sprintf("   Amenaza: %s | Riesgo: %s", result.Threat, result.Risk))
	logPrintln(colorYellow, fmt.Sprintf("   Razón: %s", result.Reason))

	switch result.Action {
	case "block":
		reason := fmt.Sprintf("%s - %s (%s)", result.Threat, result.Protocol, result.Risk)
		stateManager.BlockIP(result.IP, blockTime, reason)

	case "monitor":
		logPrintln(colorYellow, fmt.Sprintf("👁️ Monitoreando IP %s por: %s", result.IP, result.Reason))

	case "allow":
		logPrintln(colorGreen, fmt.Sprintf("✅ Tráfico de %s considerado normal", result.IP))
	}
}

// --- Métodos Mejorados del StateManager ---

func (sm *StateManager) BlockIP(ip string, duration time.Duration, reason string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if blocked, exists := sm.blockedIPs[ip]; exists {
		logPrintln(colorYellow, fmt.Sprintf("⚠️ IP %s ya bloqueada hasta %v", ip, blocked.Expiry.Format("15:04:05")))
		return
	}

	// Comando Windows Firewall
	ruleName := fmt.Sprintf("IPS_Block_%s_%d", ip, time.Now().Unix())
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName, "dir=in", "action=block", "remoteip="+ip)

	if err := cmd.Run(); err != nil {
		logPrintln(colorRed, fmt.Sprintf("❌ Error bloqueando IP %s: %v", ip, err))
		return
	}

	expiry := time.Now().Add(duration)
	sm.blockedIPs[ip] = BlockedIP{
		Expiry: expiry,
		Reason: reason,
	}

	logPrintln(colorRed, fmt.Sprintf("🛡️ IP %s BLOQUEADA por %v", ip, duration))
	logPrintln(colorRed, fmt.Sprintf("   Razón: %s", reason))
	logPrintln(colorRed, fmt.Sprintf("   Expira: %s", expiry.Format("2006-01-02 15:04:05")))
}

func (sm *StateManager) UnblockIP(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.mu.Unlock()

	// Buscar y eliminar regla de firewall
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
	output, err := cmd.Output()
	if err != nil {
		logPrintln(colorRed, fmt.Sprintf("❌ Error consultando reglas firewall: %v", err))
		return
	}

	// Buscar reglas que contengan la IP bloqueada
	rules := strings.Split(string(output), "\n")
	for _, rule := range rules {
		if strings.Contains(rule, fmt.Sprintf("IPS_Block_%s", ip)) {
			// Extraer nombre de regla
			if strings.Contains(rule, "Nombre de regla:") {
				ruleName := strings.TrimSpace(strings.Split(rule, ":")[1])
				deleteCmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
				if err := deleteCmd.Run(); err != nil {
					logPrintln(colorRed, fmt.Sprintf("❌ Error eliminando regla %s: %v", ruleName, err))
				} else {
					logPrintln(colorGreen, fmt.Sprintf("🔓 Regla %s eliminada", ruleName))
				}
			}
		}
	}

	delete(sm.blockedIPs, ip)
	logPrintln(colorGreen, fmt.Sprintf("🔓 IP %s desbloqueada", ip))
}

// --- VERSIÓN CORREGIDA Y SEGURA de manageUnblocks ---
func (sm *StateManager) manageUnblocks() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock() // 1. Bloquea el mutex UNA SOLA VEZ al principio.

		var expiredIPs []string
		for ip, blockInfo := range sm.blockedIPs {
			if time.Now().After(blockInfo.Expiry) {
				expiredIPs = append(expiredIPs, ip)
			}
		}

		// Desbloquear IPs expiradas de forma SECUENCIAL Y SEGURA.
		// Ya tenemos el lock, así que no hay necesidad de llamar a UnblockIP que lo volvería a tomar.
		if len(expiredIPs) > 0 {
			logPrintln(colorCyan, "⏳ Desbloqueando IPs expiradas...")
			for _, ip := range expiredIPs {
				// Ejecutamos la lógica de desbloqueo aquí directamente.
				ruleName := getRuleName(ip)
				var cmd *exec.Cmd
				switch runtime.GOOS {
				case "windows":
					cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
				case "linux":
					cmd = exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", ruleName)
				}

				if cmd != nil {
					if err := cmd.Run(); err != nil {
						// Ignoramos el error "not found", es normal si la regla ya fue borrada manualmente.
						if !isNotFoundError(err.Error()) {
							logPrintln(colorYellow, fmt.Sprintf("⚠️ No se pudo eliminar la regla para %s: %v", ip, err))
						}
					}
				}

				// Eliminar del estado interno.
				delete(sm.blockedIPs, ip)
				logPrintln(colorGreen, fmt.Sprintf("🔓 IP %s desbloqueada.", ip))
			}
		}

		// Mostrar estado actual de bloqueos (todavía dentro del mismo lock).
		if len(sm.blockedIPs) > 0 {
			logPrintln(colorMagenta, fmt.Sprintf("🔒 IPs bloqueadas activas: %d", len(sm.blockedIPs)))
			for ip, info := range sm.blockedIPs {
				remaining := time.Until(info.Expiry)
				if remaining > 0 {
					fmt.Printf("   %s%s: %v restante (%s)%s\n",
						colorMagenta, ip, remaining.Round(time.Second), info.Reason, colorReset)
				}
			}
		}

		sm.mu.Unlock() // 2. Desbloquea el mutex UNA SOLA VEZ al final.
	}
}

func (sm *StateManager) GetBlockedCount() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return len(sm.blockedIPs)
}

func (sm *StateManager) IsBlocked(ip string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	_, exists := sm.blockedIPs[ip]
	return exists
}

// getRuleName generates a consistent rule name for firewall operations.
func getRuleName(ip string) string {
	return fmt.Sprintf("IPS_Block_%s", ip)
}

// isNotFoundError checks if the error message indicates a "not found" condition for firewall rules.
// This is a simple string match and might need refinement for different OS/firewall outputs.
func isNotFoundError(errMsg string) bool {
	return strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "no rules matching")
}
