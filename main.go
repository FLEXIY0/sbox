// sbox — "непробиваемый" TUI-клиент для sing-box.
//
// Один бинарник, два слоя:
//   - Daemon Engine  (sbox --daemon): качает подписку, генерирует config.json,
//     запускает sing-box, пингует ноды, авто-ротация.
//   - TUI            (sbox):          raw-mode интерфейс поверх текущего буфера
//     терминала (без alternate screen), общается с демоном по IPC.
//
// Кросс-платформенность: Linux (amd64/arm64/armv7/mips), Windows, macOS.
// Платформенные различия вынесены в platform_unix.go / platform_windows.go.
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

const (
	appVersion  = "v1.0.3"
	repoOwner   = "flexiy0"
	repoName    = "sbox"
	clashAPI    = "127.0.0.1:9095"
	mixedPort   = 2080
	geoipRuURL  = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs"
	ruBundleURL = "https://raw.githubusercontent.com/legiz-ru/sb-rule-sets/main/ru-bundle.srs"
)

// ---------------------------------------------------------------------------
// Настройки и состояние
// ---------------------------------------------------------------------------

type Settings struct {
	SubURL         string `json:"sub_url"`
	TestURL        string `json:"test_url"`
	Limit          int    `json:"limit"`
	AutoRotate     bool   `json:"auto_rotate"`
	RotateInterval int    `json:"rotate_interval_sec"`
}

func defaultSettings() Settings {
	return Settings{
		TestURL:        "http://cp.cloudflare.com/generate_204",
		Limit:          15,
		AutoRotate:     true,
		RotateInterval: 60,
	}
}

type Node struct {
	ID       int    `json:"id"`
	Tag      string `json:"tag"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Latency  int    `json:"latency_ms"` // -1 = не проверен, -2 = DEAD
	outbound map[string]any
}

type Status struct {
	Version    string   `json:"version"`
	Settings   Settings `json:"settings"`
	Nodes      []Node   `json:"nodes"` // топ-N по задержке (для показа)
	TotalNodes int      `json:"total_nodes"`
	Tested     int      `json:"tested"`
	ActiveTag  string   `json:"active_tag"`
	Source     string   `json:"source"` // LIVE / GITHUB | OFFLINE / LOCAL CACHE
	Daemon     string   `json:"daemon"` // systemd | local | schtasks
	AllDead    bool     `json:"all_dead"`
	LastError  string   `json:"last_error"`
	SingBoxRun bool     `json:"sing_box_running"`
}

// maxScanNodes — верхний предел числа нод, которые мы загружаем из подписки
// и тестируем. Settings.Limit при этом задаёт лишь, сколько ЛУЧШИХ показать.
const maxScanNodes = 200

type ipcRequest struct {
	Cmd string `json:"cmd"` // status | select | update | toggle_rotate | test | reload | stop
	Arg string `json:"arg,omitempty"`
}

func dataDir() string {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		return "/var/lib/sbox"
	}
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "sbox")
}

func settingsPath() string { return filepath.Join(dataDir(), "settings.json") }
func cachePath() string    { return filepath.Join(dataDir(), "last_good_sub.txt") }
func configPath() string   { return filepath.Join(dataDir(), "config.json") }

func loadSettings() (Settings, error) {
	s := defaultSettings()
	b, err := os.ReadFile(settingsPath())
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}

func saveSettings(s Settings) error {
	if err := os.MkdirAll(dataDir(), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(settingsPath(), b, 0o644)
}

// resetAll останавливает демон и удаляет настройки, кэш подписки и конфиг —
// следующий запуск `sbox` заново проходит мастер настройки.
func resetAll() error {
	if conn, err := dialIPC(dataDir()); err == nil {
		json.NewEncoder(conn).Encode(ipcRequest{Cmd: "stop"})
		conn.Close()
		time.Sleep(500 * time.Millisecond)
	}
	for _, p := range []string{
		settingsPath(), cachePath(), configPath(),
		filepath.Join(dataDir(), "cache.db"),
	} {
		os.Remove(p)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Парсинг ссылок подписки -> outbound-объекты sing-box
// ---------------------------------------------------------------------------

func maybeBase64(s string) string {
	trimmed := strings.TrimSpace(s)
	if strings.Contains(trimmed, "://") {
		return trimmed
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(strings.ReplaceAll(trimmed, "\n", "")); err == nil {
			return string(b)
		}
	}
	return trimmed
}

func parseSubscription(raw string, limit int) []Node {
	text := maybeBase64(raw)
	var nodes []Node
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n, err := parseLink(line, len(nodes)+1)
		if err != nil {
			continue
		}
		if err := validOutbound(n.outbound); err != nil {
			// Битую ноду молча пропускаем: один невалидный outbound
			// (пустой uuid, отсутствующий reality public_key и т.п.)
			// заставляет sing-box отвергнуть ВЕСЬ конфиг и не стартовать.
			logf("skipping node %d (%s): %v", n.ID, n.Type, err)
			continue
		}
		n.ID = len(nodes) + 1
		n.Tag = fmt.Sprintf("node-%02d", n.ID)
		n.outbound["tag"] = n.Tag
		nodes = append(nodes, n)
		if len(nodes) >= limit {
			break
		}
	}
	return nodes
}

// validOutbound отбраковывает нежизнеспособные ноды до попадания в конфиг.
// sing-box валидирует весь файл целиком при старте, поэтому одна битая
// ссылка из бесплатного списка обрушивает запуск ядра.
func validOutbound(ob map[string]any) error {
	str := func(k string) string {
		s, _ := ob[k].(string)
		return s
	}
	if str("server") == "" {
		return errors.New("empty server")
	}
	if p, _ := ob["server_port"].(int); p <= 0 || p > 65535 {
		return fmt.Errorf("bad port %v", ob["server_port"])
	}
	switch ob["type"] {
	case "vless", "vmess", "tuic":
		if str("uuid") == "" {
			return errors.New("empty uuid")
		}
	case "trojan", "hysteria2":
		if str("password") == "" {
			return errors.New("empty password")
		}
	case "shadowsocks":
		if str("method") == "" || str("password") == "" {
			return errors.New("empty method/password")
		}
	}
	if tls, ok := ob["tls"].(map[string]any); ok {
		if r, ok := tls["reality"].(map[string]any); ok {
			if pk, _ := r["public_key"].(string); pk == "" {
				return errors.New("reality without public_key")
			}
		}
	}
	return nil
}

func parseLink(link string, id int) (Node, error) {
	scheme := link[:strings.Index(link, "://")+0]
	if i := strings.Index(link, "://"); i > 0 {
		scheme = strings.ToLower(link[:i])
	}
	tag := fmt.Sprintf("node-%02d", id)
	var (
		ob   map[string]any
		name string
		err  error
	)
	switch scheme {
	case "vless":
		ob, name, err = parseVless(link)
	case "vmess":
		ob, name, err = parseVmess(link)
	case "trojan":
		ob, name, err = parseTrojan(link)
	case "ss":
		ob, name, err = parseShadowsocks(link)
	case "hysteria2", "hy2":
		ob, name, err = parseHysteria2(link)
	case "tuic":
		ob, name, err = parseTuic(link)
	default:
		return Node{}, fmt.Errorf("unsupported scheme %q", scheme)
	}
	if err != nil {
		return Node{}, err
	}
	ob["tag"] = tag
	if name == "" {
		name = fmt.Sprintf("%s-%s", strings.ToUpper(scheme), ob["server"])
	}
	return Node{ID: id, Tag: tag, Name: sanitizeName(name), Type: strings.ToUpper(scheme), Latency: -1, outbound: ob}, nil
}

func sanitizeName(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		default:
			// не-ASCII символы (флаги, эмодзи) выбрасываем ради совместимости
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "NODE"
	}
	if len(out) > 26 {
		out = out[:26]
	}
	return out
}

func hostPort(u *url.URL) (string, int) {
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	return u.Hostname(), port
}

func tlsBlock(q url.Values, host string) map[string]any {
	sec := q.Get("security")
	if sec != "tls" && sec != "reality" {
		return nil
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = host
	}
	tls := map[string]any{"enabled": true, "server_name": sni}
	if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
		tls["insecure"] = true
	}
	if fp := q.Get("fp"); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if sec == "reality" {
		tls["reality"] = map[string]any{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}
	}
	return tls
}

func transportBlock(q url.Values) map[string]any {
	switch q.Get("type") {
	case "ws":
		t := map[string]any{"type": "ws", "path": q.Get("path")}
		if h := q.Get("host"); h != "" {
			t["headers"] = map[string]any{"Host": h}
		}
		return t
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": q.Get("serviceName")}
	case "http", "h2":
		return map[string]any{"type": "http", "path": q.Get("path")}
	}
	return nil
}

func parseVless(link string) (map[string]any, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", err
	}
	host, port := hostPort(u)
	q := u.Query()
	ob := map[string]any{"type": "vless", "server": host, "server_port": port, "uuid": u.User.Username()}
	if flow := q.Get("flow"); flow != "" {
		ob["flow"] = flow
	}
	if tls := tlsBlock(q, host); tls != nil {
		ob["tls"] = tls
	}
	if tr := transportBlock(q); tr != nil {
		ob["transport"] = tr
	}
	name := u.Fragment
	if q.Get("security") == "reality" {
		name = "REALITY-" + name
	}
	return ob, name, nil
}

func parseVmess(link string) (map[string]any, string, error) {
	payload := strings.TrimPrefix(link, "vmess://")
	decoded := maybeBase64(payload)
	var v struct {
		Ps   string          `json:"ps"`
		Add  string          `json:"add"`
		Port json.RawMessage `json:"port"`
		ID   string          `json:"id"`
		Aid  json.RawMessage `json:"aid"`
		Scy  string          `json:"scy"`
		Net  string          `json:"net"`
		Host string          `json:"host"`
		Path string          `json:"path"`
		TLS  string          `json:"tls"`
		SNI  string          `json:"sni"`
	}
	if err := json.Unmarshal([]byte(decoded), &v); err != nil {
		return nil, "", err
	}
	port, _ := strconv.Atoi(strings.Trim(string(v.Port), `"`))
	aid, _ := strconv.Atoi(strings.Trim(string(v.Aid), `"`))
	sec := v.Scy
	if sec == "" {
		sec = "auto"
	}
	ob := map[string]any{"type": "vmess", "server": v.Add, "server_port": port, "uuid": v.ID, "security": sec, "alter_id": aid}
	if v.TLS == "tls" {
		sni := v.SNI
		if sni == "" {
			sni = v.Add
		}
		ob["tls"] = map[string]any{"enabled": true, "server_name": sni}
	}
	q := url.Values{"type": {v.Net}, "path": {v.Path}, "host": {v.Host}, "serviceName": {v.Path}}
	if tr := transportBlock(q); tr != nil {
		ob["transport"] = tr
	}
	return ob, v.Ps, nil
}

func parseTrojan(link string) (map[string]any, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", err
	}
	host, port := hostPort(u)
	q := u.Query()
	ob := map[string]any{"type": "trojan", "server": host, "server_port": port, "password": u.User.Username()}
	sni := q.Get("sni")
	if sni == "" {
		sni = host
	}
	tls := map[string]any{"enabled": true, "server_name": sni}
	if q.Get("allowInsecure") == "1" {
		tls["insecure"] = true
	}
	ob["tls"] = tls
	if tr := transportBlock(q); tr != nil {
		ob["transport"] = tr
	}
	return ob, u.Fragment, nil
}

func parseShadowsocks(link string) (map[string]any, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", err
	}
	var method, password, host string
	var port int
	if u.User != nil {
		userinfo := u.User.Username()
		if pw, ok := u.User.Password(); ok {
			method, password = userinfo, pw
		} else {
			dec := maybeBase64(userinfo)
			parts := strings.SplitN(dec, ":", 2)
			if len(parts) != 2 {
				return nil, "", errors.New("bad ss userinfo")
			}
			method, password = parts[0], parts[1]
		}
		host, port = hostPort(u)
	} else {
		// ss://base64(method:pass@host:port)
		dec := maybeBase64(strings.TrimPrefix(strings.SplitN(link, "#", 2)[0], "ss://"))
		u2, err := url.Parse("ss://" + dec)
		if err != nil || u2.User == nil {
			return nil, "", errors.New("bad ss link")
		}
		method = u2.User.Username()
		password, _ = u2.User.Password()
		host, port = hostPort(u2)
	}
	ob := map[string]any{"type": "shadowsocks", "server": host, "server_port": port, "method": method, "password": password}
	return ob, u.Fragment, nil
}

func parseHysteria2(link string) (map[string]any, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", err
	}
	host, port := hostPort(u)
	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = host
	}
	tls := map[string]any{"enabled": true, "server_name": sni}
	if q.Get("insecure") == "1" {
		tls["insecure"] = true
	}
	ob := map[string]any{"type": "hysteria2", "server": host, "server_port": port, "password": u.User.String(), "tls": tls}
	if obfs := q.Get("obfs"); obfs != "" {
		ob["obfs"] = map[string]any{"type": obfs, "password": q.Get("obfs-password")}
	}
	return ob, u.Fragment, nil
}

func parseTuic(link string) (map[string]any, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", err
	}
	host, port := hostPort(u)
	q := u.Query()
	pass, _ := u.User.Password()
	sni := q.Get("sni")
	if sni == "" {
		sni = host
	}
	tls := map[string]any{"enabled": true, "server_name": sni}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if q.Get("allow_insecure") == "1" || q.Get("insecure") == "1" {
		tls["insecure"] = true
	}
	ob := map[string]any{"type": "tuic", "server": host, "server_port": port, "uuid": u.User.Username(), "password": pass, "tls": tls}
	if cc := q.Get("congestion_control"); cc != "" {
		ob["congestion_control"] = cc
	}
	return ob, u.Fragment, nil
}

// ---------------------------------------------------------------------------
// Генерация config.json (сплит-туннелирование RU -> direct)
// ---------------------------------------------------------------------------

func generateConfig(nodes []Node, s Settings) []byte {
	outbounds := []any{}
	tags := []any{}
	for _, n := range nodes {
		outbounds = append(outbounds, n.outbound)
		tags = append(tags, n.Tag)
	}
	selector := map[string]any{"type": "selector", "tag": "proxy", "outbounds": tags, "interrupt_exist_connections": true}
	if len(nodes) > 0 {
		selector["default"] = nodes[0].Tag
	}
	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"tag": "remote", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
				map[string]any{"tag": "local", "address": "77.88.8.8", "detour": "direct"},
			},
			"rules": []any{
				map[string]any{"rule_set": []any{"ru-bundle"}, "server": "local"},
			},
			"final": "remote",
		},
		"inbounds": []any{
			map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": mixedPort},
		},
		"outbounds": append([]any{selector}, append(outbounds, map[string]any{"type": "direct", "tag": "direct"})...),
		"route": map[string]any{
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{"ip_is_private": true, "outbound": "direct"},
				map[string]any{"rule_set": []any{"geoip-ru", "ru-bundle"}, "outbound": "direct"},
			},
			// download_detour: proxy — rule-set'ы лежат на GitHub, а GitHub у
			// пользователя обычно и заблокирован (ради этого и нужен клиент).
			// Качаем их ЧЕРЕЗ прокси, иначе sing-box не сможет получить их
			// напрямую и роутер не поднимется. После первой загрузки они
			// кэшируются в cache_file.
			"rule_set": []any{
				map[string]any{"type": "remote", "tag": "geoip-ru", "format": "binary", "url": geoipRuURL, "download_detour": "proxy"},
				map[string]any{"type": "remote", "tag": "ru-bundle", "format": "binary", "url": ruBundleURL, "download_detour": "proxy"},
			},
			"final":                 "proxy",
			"auto_detect_interface": true,
		},
		"experimental": map[string]any{
			"clash_api":  map[string]any{"external_controller": clashAPI},
			"cache_file": map[string]any{"enabled": true, "path": filepath.Join(dataDir(), "cache.db")},
		},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return b
}

// ---------------------------------------------------------------------------
// Daemon Engine
// ---------------------------------------------------------------------------

type daemon struct {
	mu       sync.Mutex
	settings Settings
	nodes    []Node
	active   string
	source   string
	lastErr  string
	proc     *exec.Cmd
	http     *http.Client
}

func runDaemon() error {
	if conn, err := dialIPC(dataDir()); err == nil {
		conn.Close()
		return errors.New("daemon already running")
	}
	s, err := loadSettings()
	if err != nil && s.SubURL == "" {
		return errors.New("no settings; run `sbox` first to configure subscription URL")
	}
	if err := os.MkdirAll(dataDir(), 0o755); err != nil {
		return err
	}
	d := &daemon{settings: s, source: "OFFLINE / LOCAL CACHE", http: &http.Client{Timeout: 30 * time.Second}}

	ln, err := listenIPC(dataDir())
	if err != nil {
		return fmt.Errorf("ipc listen: %w", err)
	}
	defer ln.Close()

	stop := make(chan os.Signal, 2)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	if err := d.refresh(); err != nil {
		d.setErr(err)
	}
	go d.testLoop()
	go d.rotateLoop()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serveConn(conn)
		}
	}()

	<-stop
	d.stopSingBox()
	return nil
}

func (d *daemon) setErr(err error) {
	d.mu.Lock()
	d.lastErr = err.Error()
	d.mu.Unlock()
	logf("error: %v", err)
}

func logf(format string, a ...any) {
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
	f, err := os.OpenFile(filepath.Join(dataDir(), "daemon.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		f.WriteString(line)
		f.Close()
	}
}

// refresh: скачать подписку (или взять кэш), сгенерировать конфиг, (пере)запустить sing-box.
func (d *daemon) refresh() error {
	d.mu.Lock()
	s := d.settings
	d.mu.Unlock()

	var raw string
	resp, err := d.http.Get(s.SubURL)
	if err == nil && resp.StatusCode == 200 {
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if rerr == nil && len(b) > 0 {
			raw = string(b)
			os.WriteFile(cachePath(), b, 0o644)
			d.mu.Lock()
			d.source = "LIVE / GITHUB"
			d.mu.Unlock()
		}
	}
	if raw == "" {
		if err == nil && resp != nil {
			err = fmt.Errorf("subscription HTTP %d", resp.StatusCode)
		}
		b, cerr := os.ReadFile(cachePath())
		if cerr != nil {
			return fmt.Errorf("subscription download failed (%v) and no local cache", err)
		}
		raw = string(b)
		d.mu.Lock()
		d.source = "OFFLINE / LOCAL CACHE"
		d.mu.Unlock()
		logf("subscription download failed (%v), using local cache", err)
	}

	// Грузим ВСЕ ноды подписки (до maxScanNodes) — тестируются потом все,
	// а Settings.Limit определяет лишь, сколько лучших показать в TUI.
	nodes := parseSubscription(raw, maxScanNodes)
	if len(nodes) == 0 {
		return errors.New("subscription contains no supported links")
	}
	logf("loaded %d nodes from subscription", len(nodes))
	cfg := generateConfig(nodes, s)
	if err := os.WriteFile(configPath(), cfg, 0o644); err != nil {
		return err
	}
	d.mu.Lock()
	d.nodes = nodes
	d.active = nodes[0].Tag
	d.lastErr = ""
	d.mu.Unlock()
	return d.restartSingBox()
}

func (d *daemon) restartSingBox() error {
	d.stopSingBox()
	bin, err := ensureSingBox()
	if err != nil {
		return err
	}
	// Сначала валидируем конфиг самим sing-box — так реальная причина
	// (битая нода, несовместимый формат) видна сразу, а не маскируется
	// последующим «connection refused» к clash_api.
	if out, cerr := exec.Command(bin, "check", "-c", configPath()).CombinedOutput(); cerr != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = cerr.Error()
		}
		return fmt.Errorf("sing-box rejected config: %s", firstLine(msg))
	}
	logPath := filepath.Join(dataDir(), "sing-box.log")
	logFile, _ := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	cmd := exec.Command(bin, "run", "-c", configPath())
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = detachAttrs()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sing-box: %w", err)
	}
	d.mu.Lock()
	d.proc = cmd
	d.mu.Unlock()
	go cmd.Wait()
	logf("sing-box started (pid %d)", cmd.Process.Pid)

	// Убеждаемся, что ядро действительно поднялось: даём немного времени и
	// проверяем, что процесс не умер и clash_api отвечает. Иначе — вытаскиваем
	// хвост его лога в статус, чтобы пользователь видел настоящую ошибку.
	for i := 0; i < 12; i++ {
		time.Sleep(400 * time.Millisecond)
		if cmd.ProcessState != nil { // процесс уже завершился
			return fmt.Errorf("sing-box exited on startup: %s", tailLog(logPath))
		}
		if resp, e := d.clashGet("/version"); e == nil {
			resp.Body.Close()
			return nil // ядро живо, API отвечает
		}
	}
	if cmd.ProcessState != nil {
		return fmt.Errorf("sing-box exited on startup: %s", tailLog(logPath))
	}
	return nil // процесс жив, но API ещё не ответил — не считаем ошибкой
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// tailLog возвращает последние непустые строки лога sing-box для показа
// пользователю (обрезаем ANSI/таймстампы не трогаем — важен смысл).
func tailLog(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return "no log output (check " + path + ")"
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	from := len(lines) - 3
	if from < 0 {
		from = 0
	}
	return strings.TrimSpace(strings.Join(lines[from:], " | "))
}

func (d *daemon) stopSingBox() {
	d.mu.Lock()
	proc := d.proc
	d.proc = nil
	d.mu.Unlock()
	if proc != nil && proc.Process != nil {
		proc.Process.Kill()
		time.Sleep(300 * time.Millisecond)
	}
}

func (d *daemon) singBoxRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.proc != nil && d.proc.ProcessState == nil
}

// clash_api helpers ---------------------------------------------------------

func (d *daemon) clashGet(path string) (*http.Response, error) {
	return d.http.Get("http://" + clashAPI + path)
}

func (d *daemon) testNode(tag string, testURL string) int {
	u := fmt.Sprintf("/proxies/%s/delay?timeout=5000&url=%s", url.PathEscape(tag), url.QueryEscape(testURL))
	resp, err := d.clashGet(u)
	if err != nil {
		return -2
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return -2
	}
	var r struct {
		Delay int `json:"delay"`
	}
	if json.NewDecoder(resp.Body).Decode(&r) != nil || r.Delay <= 0 {
		return -2
	}
	return r.Delay
}

func (d *daemon) selectNode(tag string) error {
	body, _ := json.Marshal(map[string]string{"name": tag})
	req, _ := http.NewRequest(http.MethodPut, "http://"+clashAPI+"/proxies/proxy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("clash api: HTTP %d", resp.StatusCode)
	}
	d.mu.Lock()
	d.active = tag
	d.mu.Unlock()
	logf("active node -> %s", tag)
	return nil
}

func (d *daemon) testAll() {
	d.mu.Lock()
	nodes := make([]Node, len(d.nodes))
	copy(nodes, d.nodes)
	testURL := d.settings.TestURL
	d.mu.Unlock()

	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	results := make([]int, len(nodes))
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, tag string) {
			defer wg.Done()
			sem <- struct{}{}
			results[i] = d.testNode(tag, testURL)
			<-sem
		}(i, n.Tag)
	}
	wg.Wait()

	d.mu.Lock()
	for i := range d.nodes {
		if i < len(results) && d.nodes[i].Tag == nodes[i].Tag {
			d.nodes[i].Latency = results[i]
		}
	}
	d.mu.Unlock()
}

func (d *daemon) testLoop() {
	time.Sleep(3 * time.Second) // дать sing-box подняться
	first := true
	for {
		if d.singBoxRunning() {
			d.testAll()
			// После первого прогона встаём на лучшую живую ноду, чтобы не
			// сидеть на произвольной node-01, которая могла оказаться мёртвой.
			if first {
				d.mu.Lock()
				auto := d.settings.AutoRotate
				d.mu.Unlock()
				if auto {
					if best := d.bestNode(""); best != "" {
						d.selectNode(best)
					}
				}
				first = false
			}
		}
		time.Sleep(30 * time.Second)
	}
}

// bestNode возвращает тег живой ноды с минимальным пингом (кроме exclude).
func (d *daemon) bestNode(exclude string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	best := ""
	bestLat := 1 << 30
	for _, n := range d.nodes {
		if n.Latency > 0 && n.Latency < bestLat && n.Tag != exclude {
			best, bestLat = n.Tag, n.Latency
		}
	}
	return best
}

func (d *daemon) rotateLoop() {
	for {
		d.mu.Lock()
		interval := d.settings.RotateInterval
		d.mu.Unlock()
		if interval < 10 {
			interval = 60
		}
		time.Sleep(time.Duration(interval) * time.Second)

		d.mu.Lock()
		enabled := d.settings.AutoRotate
		active := d.active
		testURL := d.settings.TestURL
		d.mu.Unlock()
		if !enabled || !d.singBoxRunning() || active == "" {
			continue
		}
		if lat := d.testNode(active, testURL); lat > 0 {
			continue // активная нода жива
		}
		logf("active node %s is DEAD, rotating", active)
		d.testAll()
		if best := d.bestNode(active); best != "" {
			d.selectNode(best)
		}
	}
}

// IPC -----------------------------------------------------------------------

func (d *daemon) status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Сортируем копию по задержке: сначала живые (по возрастанию пинга),
	// затем ещё не протестированные, в конце — мёртвые. Показываем топ-Limit.
	sorted := append([]Node(nil), d.nodes...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return latencyRank(sorted[i].Latency) < latencyRank(sorted[j].Latency)
	})
	limit := d.settings.Limit
	if limit <= 0 {
		limit = 15
	}
	shown := sorted
	if len(shown) > limit {
		shown = shown[:limit]
	}

	tested, alive := 0, 0
	for _, n := range d.nodes {
		if n.Latency != -1 {
			tested++
		}
		if n.Latency > 0 {
			alive++
		}
	}
	st := Status{
		Version:    appVersion,
		Settings:   d.settings,
		Nodes:      shown,
		TotalNodes: len(d.nodes),
		Tested:     tested,
		ActiveTag:  d.active,
		Source:     d.source,
		Daemon:     serviceKind(),
		LastError:  d.lastErr,
	}
	st.SingBoxRun = d.proc != nil && d.proc.ProcessState == nil
	st.AllDead = len(d.nodes) > 0 && tested == len(d.nodes) && alive == 0
	return st
}

// latencyRank задаёт порядок сортировки: живые ноды (по пингу) < не
// протестированные (-1) < мёртвые (<=0). Возвращает ключ для сравнения.
func latencyRank(ms int) int {
	switch {
	case ms > 0:
		return ms // живые: чем меньше пинг, тем выше
	case ms == -1:
		return 1 << 20 // ещё не тестировались
	default:
		return 1 << 21 // DEAD — в самый низ
	}
}

func (d *daemon) serveConn(conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	for {
		var req ipcRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		switch req.Cmd {
		case "select":
			if err := d.selectNode(req.Arg); err != nil {
				d.setErr(err)
			}
		case "update":
			if err := d.refresh(); err != nil {
				d.setErr(err)
			}
			go func() { time.Sleep(3 * time.Second); d.testAll() }()
		case "toggle_rotate":
			d.mu.Lock()
			d.settings.AutoRotate = !d.settings.AutoRotate
			s := d.settings
			d.mu.Unlock()
			saveSettings(s)
		case "test":
			go d.testAll()
		case "reload":
			// Перечитываем настройки с диска. Если сменился URL подписки —
			// перекачиваем и перезапускаем ядро; иначе меняется только показ.
			if ns, err := loadSettings(); err == nil {
				d.mu.Lock()
				subChanged := ns.SubURL != d.settings.SubURL
				d.settings = ns
				d.mu.Unlock()
				if subChanged {
					if err := d.refresh(); err != nil {
						d.setErr(err)
					}
					go func() { time.Sleep(3 * time.Second); d.testAll() }()
				}
			}
		case "stop":
			enc.Encode(d.status())
			d.stopSingBox()
			os.Exit(0)
		}
		if err := enc.Encode(d.status()); err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Скачивание sing-box при отсутствии
// ---------------------------------------------------------------------------

func singBoxName() string {
	if runtime.GOOS == "windows" {
		return "sing-box.exe"
	}
	return "sing-box"
}

func ensureSingBox() (string, error) {
	if p, err := exec.LookPath(singBoxName()); err == nil {
		return p, nil
	}
	local := filepath.Join(dataDir(), "bin", singBoxName())
	if _, err := os.Stat(local); err == nil {
		return local, nil
	}
	logf("sing-box not found, downloading from GitHub releases...")
	if err := downloadSingBox(local); err != nil {
		return "", fmt.Errorf("sing-box is not installed and auto-download failed: %w", err)
	}
	return local, nil
}

func goarchAsset() string {
	switch runtime.GOARCH {
	case "arm":
		return "armv7"
	default:
		return runtime.GOARCH
	}
}

func downloadSingBox(dest string) error {
	cli := &http.Client{Timeout: 5 * time.Minute}
	rel, err := ghLatestRelease(cli, "SagerNet", "sing-box")
	if err != nil {
		return err
	}
	want := fmt.Sprintf("%s-%s", runtime.GOOS, goarchAsset())
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	var assetURL string
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, want) && strings.HasSuffix(a.Name, ext) {
			assetURL = a.URL
			break
		}
	}
	if assetURL == "" {
		return fmt.Errorf("no sing-box asset for %s", want)
	}
	resp, err := cli.Get(assetURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	bin, err := extractBinary(data, ext, singBoxName())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dest, bin, 0o755); err != nil {
		return err
	}
	logf("sing-box %s installed to %s", rel.Tag, dest)
	return nil
}

func extractBinary(data []byte, ext, name string) ([]byte, error) {
	if ext == ".zip" {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if filepath.Base(f.Name) == name {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(rc)
			}
		}
		return nil, errors.New("binary not found in zip")
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil, errors.New("binary not found in tar.gz")
		}
		if filepath.Base(hdr.Name) == name {
			return io.ReadAll(tr)
		}
	}
}

// ---------------------------------------------------------------------------
// GitHub releases / self-update
// ---------------------------------------------------------------------------

type ghRelease struct {
	Tag    string `json:"tag_name"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func ghLatestRelease(cli *http.Client, owner, repo string) (*ghRelease, error) {
	resp, err := cli.Get(fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github api: HTTP %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

func selfUpdate() (string, error) {
	cli := &http.Client{Timeout: 5 * time.Minute}
	rel, err := ghLatestRelease(cli, repoOwner, repoName)
	if err != nil {
		return "", err
	}
	if rel.Tag == appVersion {
		return "already latest (" + appVersion + ")", nil
	}
	want := fmt.Sprintf("sbox-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	var assetURL string
	for _, a := range rel.Assets {
		if a.Name == want {
			assetURL = a.URL
			break
		}
	}
	if assetURL == "" {
		return "", fmt.Errorf("no asset %q in release %s", want, rel.Tag)
	}
	resp, err := cli.Get(assetURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	tmp := self + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	// Windows не даёт перезаписать работающий exe, но rename работающего файла разрешён.
	old := self + ".old"
	os.Remove(old)
	if err := os.Rename(self, old); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, self); err != nil {
		os.Rename(old, self)
		return "", err
	}
	if runtime.GOOS != "windows" {
		os.Remove(old)
	}
	return "updated " + appVersion + " -> " + rel.Tag + " (restart sbox to apply)", nil
}

// ---------------------------------------------------------------------------
// TUI
// ---------------------------------------------------------------------------

const (
	clrReset  = "\033[0m"
	clrGreen  = "\033[32m"
	clrRed    = "\033[31m"
	clrYellow = "\033[33m"
	clrCyan   = "\033[36m"
	clrDim    = "\033[2m"
	clrBold   = "\033[1m"
)

type tui struct {
	conn    net.Conn
	enc     *json.Encoder
	dec     *json.Decoder
	status  Status
	sel     int
	msg     string
	lines   int // сколько строк занял последний кадр
	aliasOK bool
	raw     *term.State // сохранённое состояние терминала (raw mode)
}

// enterRaw/exitRaw переключают терминал между сырым режимом (для перехвата
// клавиш) и обычным (для ввода строк в редакторе настроек).
func (t *tui) enterRaw() error {
	st, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	t.raw = st
	fmt.Print("\033[?25l") // скрыть курсор
	return nil
}

func (t *tui) exitRaw() {
	fmt.Print("\033[?25h" + clrReset) // показать курсор
	if t.raw != nil {
		term.Restore(int(os.Stdin.Fd()), t.raw)
		t.raw = nil
	}
}

func runTUI() error {
	enableVT()
	if _, err := loadSettings(); err != nil {
		if err := firstRunWizard(); err != nil {
			return err
		}
	}
	conn, err := connectOrSpawnDaemon()
	if err != nil {
		return err
	}
	t := &tui{conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(conn), aliasOK: aliasInstalled()}
	defer conn.Close()

	if err := t.call("status"); err != nil {
		return err
	}
	t.call("test")

	if err := t.enterRaw(); err != nil {
		return fmt.Errorf("raw mode: %w", err)
	}
	restore := t.exitRaw
	defer restore()

	keys := make(chan byte, 16)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				close(keys)
				return
			}
			if n > 0 {
				keys <- buf[0]
			}
		}
	}()

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	t.render()
	for {
		select {
		case <-tick.C:
			if err := t.call("status"); err != nil {
				t.msg = clrRed + "daemon connection lost" + clrReset
			}
			t.render()
		case b, ok := <-keys:
			if !ok {
				return nil
			}
			switch b {
			case 0x1b: // escape-последовательность стрелок: ESC [ A/B
				b1, b2 := <-keys, <-keys
				if b1 == '[' {
					switch b2 {
					case 'A':
						if t.sel > 0 {
							t.sel--
						}
					case 'B':
						if t.sel < len(t.status.Nodes)-1 {
							t.sel++
						}
					}
				}
			case '\r', '\n':
				if t.sel < len(t.status.Nodes) {
					tag := t.status.Nodes[t.sel].Tag
					t.callArg("select", tag)
					t.msg = clrGreen + "switched to " + t.status.Nodes[t.sel].Name + clrReset
				}
			case 'u', 'U':
				t.msg = clrYellow + "updating subscription..." + clrReset
				t.render()
				t.call("update")
				t.msg = clrGreen + "subscription updated" + clrReset
			case 'e', 'E':
				t.editSettings(keys)
			case '+', '=':
				t.setLimit(1)
			case '-', '_':
				t.setLimit(-1)
			case 'r', 'R':
				t.call("toggle_rotate")
			case 's', 'S':
				t.msg = clrYellow + "checking for updates..." + clrReset
				t.render()
				res, err := selfUpdate()
				if err != nil {
					t.msg = clrRed + "self-update: " + err.Error() + clrReset
				} else {
					t.msg = clrGreen + res + clrReset
				}
			case 'd', 'D', 'q', 0x03: // Detach: демон продолжает работать в фоне
				restore()
				fmt.Println("detached — daemon keeps running in background (`sbox` to re-attach)")
				return nil
			}
			t.render()
		}
	}
}

func (t *tui) call(cmd string) error { return t.callArg(cmd, "") }

func (t *tui) callArg(cmd, arg string) error {
	if err := t.enc.Encode(ipcRequest{Cmd: cmd, Arg: arg}); err != nil {
		return err
	}
	return t.dec.Decode(&t.status)
}

// setLimit меняет число показываемых лучших нод «на лету» (клавиши +/-).
func (t *tui) setLimit(delta int) {
	s := t.status.Settings
	s.Limit += delta
	if s.Limit < 1 {
		s.Limit = 1
	}
	saveSettings(s)
	t.call("reload")
	t.msg = fmt.Sprintf("%sshowing best %d servers%s", clrGreen, s.Limit, clrReset)
}

// readLine — простой строковый редактор поверх канала клавиш (терминал
// остаётся в raw-режиме, поэтому ввод отображаем вручную). Возвращает
// (значение, true) по Enter или ("", false) по Esc/Ctrl-C.
func (t *tui) readLine(keys chan byte, prompt, current string) (string, bool) {
	buf := []rune(current)
	redraw := func() { fmt.Printf("\r\033[K%s%s", prompt, string(buf)) }
	redraw()
	for b := range keys {
		switch b {
		case '\r', '\n':
			fmt.Print("\r\n")
			return strings.TrimSpace(string(buf)), true
		case 0x1b, 0x03: // Esc / Ctrl-C — отмена
			fmt.Print("\r\n")
			return "", false
		case 0x7f, 0x08: // Backspace
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
		default:
			if b >= 0x20 && b < 0x7f { // печатаемые ASCII
				buf = append(buf, rune(b))
			}
		}
		redraw()
	}
	return "", false
}

// editSettings — модальный редактор настроек прямо в интерфейсе: URL
// подписки, тест-URL, число лучших и интервал ротации. Ничего вводить в
// командной строке не нужно.
func (t *tui) editSettings(keys chan byte) {
	fmt.Print("\033[2J\033[H") // очистить экран под модалку
	s := t.status.Settings
	fmt.Print("\r\n" + clrBold + "  EDIT SETTINGS" + clrReset + "\r\n\r\n")
	fmt.Printf("  [1] Subscription URL : %s\r\n", s.SubURL)
	fmt.Printf("  [2] Test URL         : %s\r\n", s.TestURL)
	fmt.Printf("  [3] Show best (N)    : %d\r\n", s.Limit)
	fmt.Printf("  [4] Rotate interval  : %ds\r\n", s.RotateInterval)
	fmt.Print("\r\n  " + clrDim + "Press 1-4 to edit, 0/Esc to cancel" + clrReset + "\r\n")

	choice, ok := <-keys
	if !ok {
		return
	}
	changed, subChanged := false, false
	switch choice {
	case '1':
		if v, ok := t.readLine(keys, "  Subscription URL: ", s.SubURL); ok && v != "" {
			s.SubURL, changed, subChanged = v, true, true
		}
	case '2':
		if v, ok := t.readLine(keys, "  Test URL: ", s.TestURL); ok && v != "" {
			s.TestURL, changed = v, true
		}
	case '3':
		if v, ok := t.readLine(keys, "  Show best (N): ", strconv.Itoa(s.Limit)); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				s.Limit, changed = n, true
			}
		}
	case '4':
		if v, ok := t.readLine(keys, "  Rotate interval seconds: ", strconv.Itoa(s.RotateInterval)); ok {
			if n, err := strconv.Atoi(v); err == nil && n >= 10 {
				s.RotateInterval, changed = n, true
			}
		}
	}
	fmt.Print("\033[2J\033[H")
	t.lines = 0
	if changed {
		saveSettings(s)
		if subChanged {
			t.msg = clrYellow + "applying new subscription..." + clrReset
			t.render()
		}
		t.call("reload") // демон перечитает настройки (и перекачает подписку, если URL сменился)
		t.msg = clrGreen + "settings saved" + clrReset
	}
}

func latencyBar(ms int) string {
	switch {
	case ms == -1:
		return clrDim + "[.....] wait" + clrReset
	case ms <= 0:
		return clrRed + "[DEAD ] timed out" + clrReset
	}
	n := 1
	switch {
	case ms < 50:
		n = 5
	case ms < 80:
		n = 4
	case ms < 120:
		n = 3
	case ms < 200:
		n = 2
	}
	color := clrGreen
	if n <= 2 {
		color = clrYellow
	}
	return fmt.Sprintf("%s[%s%s]%s %dms", color, strings.Repeat("#", n), strings.Repeat(".", 5-n), clrReset, ms)
}

func onOff(b bool, on, off string) string {
	if b {
		return clrGreen + on + clrReset
	}
	return clrRed + off + clrReset
}

func (t *tui) render() {
	st := t.status
	var b strings.Builder
	if t.lines > 0 {
		fmt.Fprintf(&b, "\033[%dF", t.lines) // курсор на начало прошлого кадра
	}
	w := func(format string, a ...any) {
		b.WriteString("\033[K") // очистить строку перед перерисовкой
		fmt.Fprintf(&b, format, a...)
		b.WriteString("\r\n")
	}

	sub := st.Settings.SubURL
	if len(sub) > 60 {
		sub = sub[:57] + "..."
	}
	w("%sSubscription:%s %s", clrBold, clrReset, sub)
	w("%sTest URL:%s     %s", clrBold, clrReset, st.Settings.TestURL)
	w("%sShow best:%s    %d  (of %d loaded, %d tested)", clrBold, clrReset, st.Settings.Limit, st.TotalNodes, st.Tested)
	w("%sAUTO-ROTATE:%s  %s (%ds interval)", clrBold, clrReset,
		onOff(st.Settings.AutoRotate, "[ON]", "[OFF]"), st.Settings.RotateInterval)
	daemonLbl := "[LOCAL / NO " + strings.ToUpper(serviceManagerName()) + "]"
	if st.Daemon != "local" {
		daemonLbl = "[ACTIVE] (" + st.Daemon + ")"
	}
	srcLbl := "[" + st.Source + "]"
	srcColor := clrGreen
	if strings.Contains(st.Source, "OFFLINE") {
		srcColor = clrYellow
	}
	w("%sDAEMON:%s       %s  |  %sSOURCE:%s  %s%s%s", clrBold, clrReset, onOff(st.Daemon != "local", daemonLbl, daemonLbl),
		clrBold, clrReset, srcColor, srcLbl, clrReset)
	alias := "[s] NOT SET"
	if t.aliasOK {
		alias = "[s] INSTALLED"
	}
	w("%sVERSION:%s      %s  |  %sALIAS:%s   %s", clrBold, clrReset, st.Version, clrBold, clrReset, alias)
	w("")
	w("%s----- TOP %d OF %d SERVERS (sorted by latency) ------------------%s", clrDim, len(st.Nodes), st.TotalNodes, clrReset)
	w("      ID | %-26s | LATENCY", "TYPE")
	for i, n := range st.Nodes {
		ptr := "  "
		if i == t.sel {
			ptr = clrCyan + "->" + clrReset
		}
		active := ""
		if n.Tag == st.ActiveTag {
			active = clrGreen + "  (* ACTIVE)" + clrReset
		}
		w("  %s  %02d | %-26s | %s%s", ptr, n.ID, n.Name, latencyBar(n.Latency), active)
	}
	if len(st.Nodes) == 0 {
		w("  %s(no nodes — press [U] to fetch subscription)%s", clrDim, clrReset)
	}
	w("%s-----------------------------------------------------------------%s", clrDim, clrReset)
	if st.AllDead {
		w("%s%s !!! ALL NODES ARE DEAD — CHECK NETWORK / PRESS [U] TO FORCE-UPDATE SUBSCRIPTION !!! %s", clrBold, clrRed, clrReset)
	}
	if st.LastError != "" {
		w("%sERR: %s%s", clrRed, st.LastError, clrReset)
	}
	if t.msg != "" {
		w("%s", t.msg)
	}
	w("%s[ENTER] Apply | [E] Edit settings | [+/-] Show more/less | [U] Update Sub | [R] Rotate%s", clrDim, clrReset)
	w("%s[S] Self-Update | [D] Detach | [Up/Down] Navigate%s", clrDim, clrReset)

	frame := b.String()
	t.lines = strings.Count(frame, "\r\n")
	fmt.Print(frame)
}

// ---------------------------------------------------------------------------
// Первый запуск / подключение к демону
// ---------------------------------------------------------------------------

func firstRunWizard() error {
	s := defaultSettings()
	rd := bufio.NewReader(os.Stdin)
	fmt.Println(clrBold + "sbox " + appVersion + " — first run setup" + clrReset)
	fmt.Print("Subscription URL (raw .txt, e.g. https://raw.githubusercontent.com/.../subs.txt):\n> ")
	line, err := rd.ReadString('\n')
	if err != nil {
		return err
	}
	s.SubURL = strings.TrimSpace(line)
	if s.SubURL == "" {
		return errors.New("subscription URL is required")
	}
	fmt.Printf("Latency test URL [%s]:\n> ", s.TestURL)
	if line, _ = rd.ReadString('\n'); strings.TrimSpace(line) != "" {
		s.TestURL = strings.TrimSpace(line)
	}
	fmt.Printf("How many BEST servers to show (all are scanned & tested) [%d]:\n> ", s.Limit)
	if line, _ = rd.ReadString('\n'); strings.TrimSpace(line) != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && n > 0 {
			s.Limit = n
		}
	}
	if err := saveSettings(s); err != nil {
		return err
	}
	fmt.Println(clrGreen + "settings saved to " + settingsPath() + clrReset)
	return nil
}

func connectOrSpawnDaemon() (net.Conn, error) {
	if conn, err := dialIPC(dataDir()); err == nil {
		return conn, nil
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	fmt.Println(clrDim + "daemon not running, starting in background..." + clrReset)
	cmd := exec.Command(self, "--daemon")
	cmd.SysProcAttr = detachAttrs()
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn daemon: %w", err)
	}
	go cmd.Process.Release()
	for i := 0; i < 40; i++ {
		time.Sleep(250 * time.Millisecond)
		if conn, err := dialIPC(dataDir()); err == nil {
			return conn, nil
		}
	}
	return nil, errors.New("daemon did not start (see " + filepath.Join(dataDir(), "daemon.log") + ")")
}

func aliasInstalled() bool {
	if runtime.GOOS == "windows" {
		home, _ := os.UserHomeDir()
		prof := filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1")
		b, err := os.ReadFile(prof)
		if err != nil {
			prof = filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1")
			b, err = os.ReadFile(prof)
		}
		return err == nil && strings.Contains(string(b), "Set-Alias -Name s ")
	}
	home, _ := os.UserHomeDir()
	for _, rc := range []string{".bashrc", ".zshrc"} {
		if b, err := os.ReadFile(filepath.Join(home, rc)); err == nil && strings.Contains(string(b), `alias s="sbox"`) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	daemonMode := flag.Bool("daemon", false, "run daemon engine in foreground")
	update := flag.Bool("update", false, "self-update from GitHub releases and exit")
	installSvc := flag.Bool("install-service", false, "install background service ("+serviceManagerName()+") and exit")
	stopFlag := flag.Bool("stop", false, "stop the running daemon and exit")
	subURL := flag.String("sub", "", "set subscription URL and exit")
	limitFlag := flag.Int("limit", 0, "set how many best servers to show and exit")
	resetFlag := flag.Bool("reset", false, "wipe settings, cache and config, stop daemon, then reconfigure on next run")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	switch {
	case *showVer:
		fmt.Println("sbox", appVersion, runtime.GOOS+"/"+runtime.GOARCH)
	case *resetFlag:
		fatal(resetAll())
		fmt.Println("reset done — run `sbox` (or `s`) to reconfigure from scratch")
	case *limitFlag > 0:
		s, _ := loadSettings()
		s.Limit = *limitFlag
		fatal(saveSettings(s))
		// Если демон запущен — попросим переприменить настройки на лету.
		if conn, err := dialIPC(dataDir()); err == nil {
			json.NewEncoder(conn).Encode(ipcRequest{Cmd: "reload"})
			conn.Close()
		}
		fmt.Printf("now showing best %d servers\n", *limitFlag)
	case *update:
		res, err := selfUpdate()
		fatal(err)
		fmt.Println(res)
	case *installSvc:
		fatal(installService())
		fmt.Println("service installed and started (" + serviceManagerName() + ")")
	case *subURL != "":
		s, _ := loadSettings()
		s.SubURL = *subURL
		fatal(saveSettings(s))
		fmt.Println("subscription URL saved")
	case *stopFlag:
		conn, err := dialIPC(dataDir())
		if err != nil {
			fmt.Println("daemon is not running")
			return
		}
		json.NewEncoder(conn).Encode(ipcRequest{Cmd: "stop"})
		conn.Close()
		fmt.Println("daemon stopped")
	case *daemonMode:
		fatal(runDaemon())
	default:
		fatal(runTUI())
	}
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, clrRed+"error:"+clrReset, err)
		os.Exit(1)
	}
}
