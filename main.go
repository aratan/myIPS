// Este es un sniffer de red y un Sistema de Prevención de Intrusiones (IPS) básico.
// Creado en Go, utiliza gopacket para la captura de paquetes y se integra con
// un Modelo de Lenguaje Grande (LLM) a través de Ollama para el análisis de amenazas.
//
// --- GUÍA RÁPIDA DE USO ---
//
// 1. Compilar y preparar dependencias (solo la primera vez):
//    go mod init sniffer-ips
//    go get github.com/google/gopacket
//    go get github.com/spf13/cobra@latest
//
// 2. Listar interfaces de red para encontrar el ID correcto:
//    go run main.go -l
//
// 3. Ejecutar el sniffer en la interfaz deseada (Wi-Fi/Ethernet):
//    go run main.go -i <ID-DE-TU-INTERFAZ-WIFI-O-ETHERNET>
//
// 4. Ejecutar en la interfaz de Loopback para pruebas locales (servidor y cliente en el mismo PC):
//    go run main.go -i <ID-DE-LA-INTERFAZ-LOOPBACK>
//
// 5. Filtrar para ver solo tráfico web (HTTP):
//    go run main.go -i <ID-INTERFAZ> -f "tcp port 80"
//
// 6. Ejecución avanzada (guardar en archivo, cambiar modelo, etc.):
//    go run main.go -i <ID> --model llama3 -t 1m -b 30m -o captura.pcap
//
// **IMPORTANTE**: El programa debe ejecutarse con privilegios de administrador.
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
)

// --- Estructuras para la comunicación con Ollama y gestión de estado ---
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
	Action string `json:"action"`
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

type BlockedIP struct {
	Expiry time.Time
}

type StateManager struct {
	mu         sync.Mutex
	blockedIPs map[string]BlockedIP
}

// --- Variables Globales ---
var (
	packetSummary = make(map[string]int)
	summaryMutex  sync.Mutex
	stateManager  = &StateManager{
		blockedIPs: make(map[string]BlockedIP),
	}
	localIPs map[string]bool
)

// --- Funciones de Utilidad ---

// listInterfaces muestra todas las interfaces de red que pcap puede detectar.
func listInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error al buscar dispositivos: %v", err)
	}

	fmt.Println("Interfaces de red disponibles:")
	for _, device := range devices {
		fmt.Printf("\n- Descripción: %s\n", device.Description)
		guid := strings.TrimPrefix(device.Name, "\\Device\\NPF_")
		fmt.Printf("  ID para usar con -i: %s\n", guid)
		for _, address := range device.Addresses {
			fmt.Printf("  - Dirección IP: %s\n", address.IP)
		}
	}
}

// getLocalIPs obtiene las IPs de la máquina local para diferenciar tráfico entrante y saliente.
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
			continue // Ignorar direcciones IPv6 por ahora
		}
		ips[ip.String()] = true
	}
	return ips, nil
}

// --- Función Principal ---
func main() {
	logFile, err := os.OpenFile("sniffer_ips.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
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
	)

	var rootCmd = &cobra.Command{
		Use:   "sniffer-ips",
		Short: "Sniffer de red con análisis y respuesta automática usando un LLM",
		Run: func(cmd *cobra.Command, args []string) {
			if shouldListInterfaces {
				listInterfaces()
				return
			}

			if interfaceID == "" {
				log.Fatal("Error: Debes especificar el ID de la interfaz con -i. Usa -l para ver las interfaces disponibles.")
			}

			var initErr error
			localIPs, initErr = getLocalIPs()
			if initErr != nil {
				log.Fatalf("Error: No se pudieron obtener las direcciones IP locales: %v", initErr)
			}
			fmt.Println("IPs locales detectadas (para análisis [IN]/[OUT]):", localIPs)

			runSniffer(interfaceID, filter, outputFile, ollamaModel, ollamaURL, analysisInterval, blockDuration)
		},
	}

	rootCmd.Flags().StringVarP(&interfaceID, "interface", "i", "", "ID de la interfaz de red (obligatorio si no se usa -l)")
	rootCmd.Flags().BoolVarP(&shouldListInterfaces, "list-interfaces", "l", false, "Lista todas las interfaces de red disponibles y sale")
	rootCmd.Flags().StringVarP(&filter, "filter", "f", "ip", "Filtro BPF para la captura de paquetes")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Archivo .pcap para guardar los paquetes capturados")
	rootCmd.Flags().StringVar(&ollamaModel, "model", "gemma3:4b", "Modelo de Ollama a utilizar para el análisis")
	rootCmd.Flags().StringVar(&ollamaURL, "url", "http://localhost:11434/api/generate", "URL de la API de Ollama")
	rootCmd.Flags().DurationVarP(&analysisInterval, "interval", "t", 30*time.Second, "Intervalo de tiempo para analizar el tráfico acumulado")
	rootCmd.Flags().DurationVarP(&blockDuration, "block-duration", "b", 15*time.Minute, "Duración del bloqueo de una IP detectada como maliciosa")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// --- Lógica Principal del Sniffer ---

func runSniffer(interfaceID, filter, output, ollamaModel, ollamaURL string, interval, blockTime time.Duration) {
	device := "\\Device\\NPF_{" + interfaceID + "}"
	handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error al abrir el adaptador %s: %v", device, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Error al aplicar filtro '%s': %v", filter, err)
	}
	logPrintln(colorGreen, fmt.Sprintf("🟢 Capturando en interfaz %s con filtro: '%s' | Modelo LLM: '%s'", interfaceID, filter, ollamaModel))

	var pcapWriter *pcapgo.Writer
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			log.Fatalf("Error al crear archivo %s: %v", output, err)
		}
		defer f.Close()
		pcapWriter = pcapgo.NewWriter(f)
		pcapWriter.WriteFileHeader(65535, layers.LinkTypeEthernet)
		logPrintln(colorCyan, fmt.Sprintf("💾 Guardando paquetes en: %s", output))
	}

	go analysisScheduler(interval, blockTime, ollamaModel, ollamaURL)
	go stateManager.manageUnblocks()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if pcapWriter != nil {
			pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	var srcIP, dstIP, logEntry, logColor string
	var directionTag string

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	srcIP = ip.SrcIP.String()
	dstIP = ip.DstIP.String()

	if localIPs[srcIP] {
		directionTag = "[OUT]"
		logColor = colorBlue
	} else if localIPs[dstIP] {
		directionTag = "[IN] "
		logColor = colorRed
	} else {
		// Tráfico entre dos IPs externas que nuestra tarjeta de red ve (ej. en modo promiscuo)
		directionTag = "[FWD]"
		logColor = colorYellow
	}

	switch {
	case packet.Layer(layers.LayerTypeTCP) != nil:
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		logEntry = fmt.Sprintf("%s [TCP] %s:%d → %s:%d", directionTag, srcIP, tcp.SrcPort, dstIP, tcp.DstPort)

		if directionTag == "[IN] " {
			summaryMutex.Lock()
			packetSummary[fmt.Sprintf("TCP_CONN_ATTEMPT_FROM_%s", srcIP)]++
			summaryMutex.Unlock()
		}

		if tcp.DstPort == 80 || tcp.SrcPort == 80 {
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				payload := appLayer.Payload()
				if len(payload) > 0 {
					fmt.Println(logColor + logEntry + colorReset)
					httpContent := string(payload)
					httpLog := fmt.Sprintf("    %s [HTTP Content]\n%s", directionTag, httpContent)
					fmt.Println(colorPurple + httpLog + colorReset)
					return
				}
			}
		}

	case packet.Layer(layers.LayerTypeUDP) != nil:
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		logEntry = fmt.Sprintf("%s [UDP] %s:%d → %s:%d", directionTag, srcIP, udp.SrcPort, dstIP, udp.DstPort)
		if directionTag == "[IN] " {
			summaryMutex.Lock()
			packetSummary[fmt.Sprintf("UDP_PACKET_FROM_%s", srcIP)]++
			summaryMutex.Unlock()
		}

	case packet.Layer(layers.LayerTypeICMPv4) != nil:
		logEntry = fmt.Sprintf("%s [ICMP] %s → %s", directionTag, srcIP, dstIP)
		if directionTag == "[IN] " {
			logColor = colorMagenta
			summaryMutex.Lock()
			packetSummary[fmt.Sprintf("ICMP_PING_FROM_%s", srcIP)]++
			summaryMutex.Unlock()
		} else {
			logColor = colorGreen
		}

	default:
		logEntry = fmt.Sprintf("%s [Otro] Paquete desde %s a %s", directionTag, srcIP, dstIP)
		logColor = colorYellow
	}

	fmt.Println(logColor + logEntry + colorReset)
}

// --- Lógica de Análisis con IA ---

func analysisScheduler(interval, blockTime time.Duration, model, url string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		summaryMutex.Lock()
		if len(packetSummary) == 0 {
			summaryMutex.Unlock()
			continue
		}
		currentSummary := packetSummary
		packetSummary = make(map[string]int)
		summaryMutex.Unlock()
		prompt := buildPrompt(currentSummary)
		logPrintln(colorCyan, fmt.Sprintf("🤖 Enviando resumen de tráfico ENTRANTE a Ollama (intervalo: %.0fs)...", interval.Seconds()))
		go sendToOllama(prompt, model, url, blockTime)
	}
}

func buildPrompt(summary map[string]int) string {
	var summaryLines []string
	for key, count := range summary {
		summaryLines = append(summaryLines, fmt.Sprintf("- %s: %d times", key, count))
	}
	return fmt.Sprintf(`Eres un experto analista de ciberseguridad para un sistema de detección de intrusiones (IPS).
Tu tarea es analizar el siguiente resumen de tráfico de red ENTRANTE. El resumen muestra el conteo de eventos por IP de origen en los últimos segundos.
Detecta patrones de ataque como escaneo de puertos (muchos TCP_CONN_ATTEMPT_FROM), fuerza bruta (similar), o ping flood (muchos ICMP_PING_FROM).
Basado en tu análisis, responde ÚNICAMENTE con un objeto JSON con la siguiente estructura:
{"action": "block" | "unblock" | "monitor", "ip": "DIRECCIÓN_IP", "reason": "MOTIVO_DEL_ANÁLISIS"}
- "action": "block" si encuentras una amenaza clara y la IP debe ser bloqueada.
- "action": "monitor" si el tráfico es sospechoso pero no concluyente, o si no hay amenaza.
- "ip": La dirección IP del presunto atacante.
- "reason": Una breve descripción en español de tu hallazgo.
Resumen de Tráfico:
%s`, strings.Join(summaryLines, "\n"))
}

func sendToOllama(prompt, model, url string, blockTime time.Duration) {
	requestData := OllamaRequest{Model: model, Prompt: prompt, Format: "json", Stream: false}
	jsonData, _ := json.Marshal(requestData)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		logPrintln(colorRed, fmt.Sprintf("❌ Error al conectar con Ollama: %v", err))
		return
	}
	defer resp.Body.Close()
	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		logPrintln(colorRed, fmt.Sprintf("❌ Error al decodificar la respuesta principal de Ollama: %v", err))
		return
	}
	var analysis AnalysisResult
	if err := json.Unmarshal([]byte(ollamaResp.Response), &analysis); err != nil {
		logPrintln(colorRed, fmt.Sprintf("❌ Error al decodificar el JSON de análisis: %v. Respuesta recibida: %s", err, ollamaResp.Response))
		return
	}
	logPrintln(colorYellow, fmt.Sprintf("🧠 Análisis de IA recibido: [Acción: %s, IP: %s, Razón: %s]", analysis.Action, analysis.IP, analysis.Reason))
	switch analysis.Action {
	case "block":
		stateManager.BlockIP(analysis.IP, blockTime)
	case "unblock":
		stateManager.UnblockIP(analysis.IP)
	case "monitor":
	}
}

// --- Métodos del StateManager para gestionar IPs ---

func (sm *StateManager) BlockIP(ip string, duration time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if _, exists := sm.blockedIPs[ip]; exists {
		logPrintln(colorYellow, fmt.Sprintf("⚠️ Intento de bloquear IP %s que ya está bloqueada.", ip))
		return
	}
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=IPS_Block_"+ip, "dir=in", "action=block", "remoteip="+ip)
	if err := cmd.Run(); err != nil {
		logPrintln(colorRed, fmt.Sprintf("❌ Error al bloquear IP %s: %v", ip, err))
	} else {
		expiry := time.Now().Add(duration)
		sm.blockedIPs[ip] = BlockedIP{Expiry: expiry}
		logPrintln(colorRed, fmt.Sprintf("🛡️ IP %s bloqueada. Se desbloqueará automáticamente en %v.", ip, duration))
	}
}

func (sm *StateManager) UnblockIP(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=IPS_Block_"+ip)
	if err := cmd.Run(); err != nil {
		logPrintln(colorRed, fmt.Sprintf("❌ Error al desbloquear IP %s: %v", ip, err))
	} else {
		delete(sm.blockedIPs, ip)
		logPrintln(colorGreen, fmt.Sprintf("🔓 IP %s desbloqueada.", ip))
	}
}

func (sm *StateManager) manageUnblocks() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		sm.mu.Lock()
		for ip, blockInfo := range sm.blockedIPs {
			if time.Now().After(blockInfo.Expiry) {
				logPrintln(colorCyan, fmt.Sprintf("⏳ Expiró el tiempo de bloqueo para %s. Intentando desbloquear...", ip))
				go sm.UnblockIP(ip)
			}
		}
		sm.mu.Unlock()
	}
}

func logPrintln(color, message string) {
	fmt.Println(color + message + colorReset)
	log.Println(message)
}