// main.go -- serve-n-collect (Go)
// Build: GOOS=linux GOARCH=amd64 go build -o serve-n-collect main.go

package main

import (
    "bufio"
    "bytes"
    "context"
    "encoding/binary"
    "flag"
    "fmt"
    "io"
    "net"
    "net/http"
    "os"
    "os/signal"
    "path/filepath"
    "strings"
    "sync"
    "syscall"
    "time"
)

var (
    httpPort    = flag.Int("http-port", 8080, "HTTP port (POST /collect)")
    tcpPort     = flag.Int("tcp-port", 4444, "TCP listener port")
    udpPort     = flag.Int("udp-port", 5000, "UDP listener port")
    dnsPort     = flag.Int("dns-port", 8053, "DNS responder port (UDP & TCP)")
    logDir      = flag.String("log-dir", "logs", "Directory for logs")
    aRecord     = flag.String("a", "127.0.0.1", "A record to return for DNS queries")
    tlsCert     = flag.String("tls-cert", "", "Path to TLS cert (optional, enables HTTPS)")
    tlsKey      = flag.String("tls-key", "", "Path to TLS key (optional, enables HTTPS)")
    readTimeout = flag.Duration("conn-read-timeout", 5*time.Second, "Read timeout for TCP connections")
)

func main() {
    flag.Parse()

    if err := os.MkdirAll(*logDir, 0750); err != nil {
        fmt.Fprintf(os.Stderr, "failed to create log dir: %v\n", err)
        os.Exit(1)
    }

    ctx, cancel := context.WithCancel(context.Background())
    wg := sync.WaitGroup{}

    // proper signal handling
    signals := make(chan os.Signal, 1)
    signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-signals
        cancel()
    }()

    fmt.Printf("serve-n-collect starting (HTTP:%d TCP:%d UDP:%d DNS:%d) logs:%s\n",
        *httpPort, *tcpPort, *udpPort, *dnsPort, *logDir)

    // HTTP server (supports optional TLS)
    wg.Add(1)
    go func() {
        defer wg.Done()
        runHTTP(ctx, *httpPort, *logDir, *tlsCert, *tlsKey)
    }()

    // TCP collector — pass pointer readTimeout (not its dereferenced value)
    wg.Add(1)
    go func() {
        defer wg.Done()
        runTCPCollector(ctx, *tcpPort, *logDir, readTimeout)
    }()

    // UDP collector
    wg.Add(1)
    go func() {
        defer wg.Done()
        runUDPCollector(ctx, *udpPort, *logDir)
    }()

    // DNS responder (UDP + TCP)
    wg.Add(1)
    go func() {
        defer wg.Done()
        runDNSResponder(ctx, *dnsPort, *logDir, *aRecord)
    }()

    //All Ports 
    wg.Add(1)
    go func() {
	defer wg.Done()
	runAllTcpBindListeners(ctx, *logDir)
    }()

    // wait until cancelled
    <-ctx.Done()
    // give goroutines a moment to finish
    time.Sleep(200 * time.Millisecond)
    wg.Wait()
    fmt.Println("serve-n-collect stopped.")
}

// appendLog appends a single line to file under dir
func appendLog(dir, fname, line string) {
    fn := filepath.Join(dir, fname)
    f, err := os.OpenFile(fn, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
    if err != nil {
        fmt.Printf("log write error (%s): %v\n", fn, err)
        return
    }
    defer f.Close()
    _, _ = f.WriteString(line + "\n")
}

// Timestamp helper
func ts() string { return time.Now().UTC().Format(time.RFC3339) }

//
// HTTP collector (POST /collect + fallback)
//
func runHTTP(ctx context.Context, port int, logDir, certPath, keyPath string) {
    mux := http.NewServeMux()

    mux.HandleFunc("/collect", func(w http.ResponseWriter, r *http.Request) {
        body, _ := io.ReadAll(r.Body)
        remote := r.RemoteAddr
        line := fmt.Sprintf("%s HTTP POST /collect from %s payload=%d", ts(), remote, len(body))
        fmt.Println(line)
        appendLog(logDir, "http.log", line)
        w.WriteHeader(200)
        _, _ = w.Write([]byte("OK"))
    })

    // fallback for other methods/paths
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        body, _ := io.ReadAll(r.Body)
        remote := r.RemoteAddr
        line := fmt.Sprintf("%s HTTP %s %s from %s payload=%d", ts(), r.Method, r.URL.Path, remote, len(body))
        fmt.Println(line)
        appendLog(logDir, "http.log", line)
        w.WriteHeader(200)
        _, _ = w.Write([]byte("OK"))
    })

    srv := &http.Server{
        Addr:    fmt.Sprintf(":%d", port),
        Handler: mux,
    }

    // shutdown on ctx cancel
    go func() {
        <-ctx.Done()
        _ = srv.Close()
    }()

    fmt.Printf("%s HTTP collector listening on :%d (tls=%v)\n", ts(), port, certPath != "" && keyPath != "")
    var err error
    if certPath != "" && keyPath != "" {
        err = srv.ListenAndServeTLS(certPath, keyPath)
    } else {
        err = srv.ListenAndServe()
    }
    if err != nil && err != http.ErrServerClosed {
        fmt.Printf("HTTP server error: %v\n", err)
    }
}

//
// TCP collector
//
func runTCPCollector(ctx context.Context, port int, logDir string, timeout *time.Duration) {
    ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
    if err != nil {
        fmt.Printf("TCP listen failed on %d: %v\n", port, err)
        return
    }
    defer ln.Close()
    fmt.Printf("%s TCP collector listening on :%d\n", ts(), port)

    for {
        ln.(*net.TCPListener).SetDeadline(time.Now().Add(500 * time.Millisecond))
        conn, err := ln.Accept()
        if err != nil {
            if ne, ok := err.(net.Error); ok && ne.Timeout() {
                select {
                case <-ctx.Done():
                    return
                default:
                    continue
                }
            }
            fmt.Printf("TCP accept error: %v\n", err)
            continue
        }
        go handleTCPConn(conn, logDir, timeout)
    }
}

func handleTCPConn(conn net.Conn, logDir string, timeout *time.Duration) {
    defer conn.Close()
    remote := conn.RemoteAddr().String()
    // read until close or timeout
    total := 0
    buf := make([]byte, 4096)
    for {
        if timeout != nil {
            _ = conn.SetReadDeadline(time.Now().Add(*timeout))
        }
        n, err := conn.Read(buf)
        if n > 0 {
            total += n
        }
        if err != nil {
            if ne, ok := err.(net.Error); ok && ne.Timeout() {
                // read timeout -> stop reading
                break
            }
            // EOF or other error -> stop
            break
        }
        // continue reading until EOF
    }
    line := fmt.Sprintf("%s TCP connection from %s received=%d", ts(), remote, total)
    fmt.Println(line)
    appendLog(logDir, "tcp.log", line)
}

//
// UDP collector
//
func runUDPCollector(ctx context.Context, port int, logDir string) {
    pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
    if err != nil {
        fmt.Printf("UDP listen failed on %d: %v\n", port, err)
        return
    }
    defer pc.Close()
    fmt.Printf("%s UDP collector listening on :%d\n", ts(), port)

    buf := make([]byte, 65535)
    for {
        _ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
        n, addr, err := pc.ReadFrom(buf)
        if err != nil {
            if ne, ok := err.(net.Error); ok && ne.Timeout() {
                select {
                case <-ctx.Done():
                    return
                default:
                    continue
                }
            }
            fmt.Printf("UDP read error: %v\n", err)
            continue
        }
        line := fmt.Sprintf("%s UDP packet from %s len=%d", ts(), addr.String(), n)
        fmt.Println(line)
        appendLog(logDir, "udp.log", line)
    }
}

//
// DNS responder (UDP + TCP)
//
func runDNSResponder(ctx context.Context, port int, logDir, aRec string) {
    wg := sync.WaitGroup{}
    wg.Add(2)
    go func() {
        defer wg.Done()
        runDNSUDP(ctx, port, logDir, aRec)
    }()
    go func() {
        defer wg.Done()
        runDNSTCP(ctx, port, logDir, aRec)
    }()
    wg.Wait()
}

func runDNSUDP(ctx context.Context, port int, logDir, aRec string) {
    pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
    if err != nil {
        fmt.Printf("DNS UDP listen failed on %d: %v\n", port, err)
        return
    }
    defer pc.Close()
    fmt.Printf("%s DNS UDP responder listening on :%d\n", ts(), port)

    buf := make([]byte, 65535)
    for {
        _ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
        n, addr, err := pc.ReadFrom(buf)
        if err != nil {
            if ne, ok := err.(net.Error); ok && ne.Timeout() {
                select {
                case <-ctx.Done():
                    return
                default:
                    continue
                }
            }
            fmt.Printf("DNS UDP read error: %v\n", err)
            continue
        }
        packet := make([]byte, n)
        copy(packet, buf[:n])
        go handleDNSQueryUDP(pc, addr, packet, logDir, aRec)
    }
}

func handleDNSQueryUDP(pc net.PacketConn, addr net.Addr, query []byte, logDir, aRec string) {
    qname := parseQName(query)
    line := fmt.Sprintf("%s DNS query UDP from %s qname=%s", ts(), addr.String(), qname)
    fmt.Println(line)
    appendLog(logDir, "dns.log", line)

    resp, err := buildDNSResponse(query, net.ParseIP(aRec).To4())
    if err != nil {
        fmt.Printf("buildDNSResponse error: %v\n", err)
        return
    }
    _, _ = pc.WriteTo(resp, addr)
}

func runDNSTCP(ctx context.Context, port int, logDir, aRec string) {
    ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
    if err != nil {
        fmt.Printf("DNS TCP listen failed on %d: %v\n", port, err)
        return
    }
    defer ln.Close()
    fmt.Printf("%s DNS TCP responder listening on :%d\n", ts(), port)

    for {
        ln.(*net.TCPListener).SetDeadline(time.Now().Add(500 * time.Millisecond))
        conn, err := ln.Accept()
        if err != nil {
            if ne, ok := err.(net.Error); ok && ne.Timeout() {
                select {
                case <-ctx.Done():
                    return
                default:
                    continue
                }
            }
            fmt.Printf("DNS TCP accept error: %v\n", err)
            continue
        }
        go handleDNSQueryTCP(conn, logDir, aRec)
    }
}

func handleDNSQueryTCP(conn net.Conn, logDir, aRec string) {
    defer conn.Close()
    // DNS over TCP is 2 byte length prefix followed by query
    br := bufio.NewReader(conn)
    lenBytes := make([]byte, 2)
    if _, err := io.ReadFull(br, lenBytes); err != nil {
        return
    }
    qLen := int(binary.BigEndian.Uint16(lenBytes))
    query := make([]byte, qLen)
    if _, err := io.ReadFull(br, query); err != nil {
        return
    }
    qname := parseQName(query)
    line := fmt.Sprintf("%s DNS query TCP from %s qname=%s", ts(), conn.RemoteAddr().String(), qname)
    fmt.Println(line)
    appendLog(logDir, "dns.log", line)

    resp, err := buildDNSResponse(query, net.ParseIP(aRec).To4())
    if err != nil {
        return
    }
    // send length prefixed response
    respLen := make([]byte, 2)
    binary.BigEndian.PutUint16(respLen, uint16(len(resp)))
    _, _ = conn.Write(respLen)
    _, _ = conn.Write(resp)
}

func parseQName(buf []byte) string {
    if len(buf) < 12 {
        return ""
    }
    pos := 12
    var labels []string
    for pos < len(buf) {
        l := int(buf[pos])
        pos++
        if l == 0 {
            break
        }
        if pos+l > len(buf) {
            break
        }
        labels = append(labels, string(buf[pos:pos+l]))
        pos += l
    }
    return strings.Join(labels, ".")
}

func buildDNSResponse(query []byte, ipV4 net.IP) ([]byte, error) {
    if len(query) < 12 {
        return nil, fmt.Errorf("invalid query")
    }
    resp := make([]byte, len(query))
    copy(resp, query)
    // flags: QR=1, AA=1 -> 0x8180 typical
    resp[2] = 0x81
    resp[3] = 0x80
    // set ANCOUNT = 1
    resp[6] = 0x00
    resp[7] = 0x01

    // append answer: pointer to name (0xC00C), type A (1), class IN (1), ttl 60, rdlength 4, rdata
    var answer bytes.Buffer
    answer.Write([]byte{0xC0, 0x0C})
    answer.Write([]byte{0x00, 0x01, 0x00, 0x01})
    _ = binary.Write(&answer, binary.BigEndian, uint32(60))
    answer.Write([]byte{0x00, 0x04})
    if ipV4 == nil || len(ipV4) != 4 {
        ipV4 = net.IPv4(127, 0, 0, 1)
    }
    answer.Write(ipV4.To4())
    return append(resp, answer.Bytes()...), nil
}

// runAllTcpBindListeners starts TCP listeners on all ports 1–65535
func runAllTcpBindListeners(ctx context.Context, logDir string) {
    fmt.Println("Starting TCP listeners on ports 1–65535")
    sem := make(chan struct{}, 1000)
    for port := 1; port <= 65535; port++ {
        select {
        case <-ctx.Done():
            return
        default:
            sem <- struct{}{}
            go func(p int) {
                defer func() { <-sem }()
                addr := fmt.Sprintf(":%d", p)
                ln, err := net.Listen("tcp", addr)
                if err != nil {
                    return
                }
                defer ln.Close()
                for {
                    ln.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
                    conn, err := ln.Accept()
                    if err != nil {
                        if ne, ok := err.(net.Error); ok && ne.Timeout() {
                            select {
                            case <-ctx.Done():
                                return
                            default:
                                continue
                            }
                        }
                        return
                    }
                    go handleAnyTCPConn(conn, logDir, p)
                }
            }(port)
        }
    }
}

// handleAnyTCPConn logs incoming TCP data per port
func handleAnyTCPConn(conn net.Conn, logDir string, port int) {
    defer conn.Close()
    remote := conn.RemoteAddr().String()
    total := 0
    buf := make([]byte, 1024)
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    for {
        n, err := conn.Read(buf)
        if n > 0 {
            total += n
        }
        if err != nil {
            break
        }
    }
    line := fmt.Sprintf("%s TCP any-port connection from %s on port %d received=%d", ts(), remote, port, total)
    fmt.Println(line)
    appendLog(logDir, fmt.Sprintf("tcp_%d.log", port), line)
}

