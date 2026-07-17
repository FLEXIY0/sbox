package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

var sampleSub = `vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&sni=yahoo.com&pbk=PUBKEY&sid=abcd&fp=chrome&type=tcp&flow=xtls-rprx-vision#Germany 🇩🇪
hysteria2://password123@5.6.7.8:8443/?sni=example.com&insecure=1#Finland
vmess://` + vmessB64 + `
trojan://pass@9.9.9.9:443?sni=cdn.example.com#TrojanNode
ss://YWVzLTI1Ni1nY206c2VjcmV0cGFzcw==@2.2.2.2:8388#SS-Node
tuic://11111111-2222-3333-4444-555555555555:pw@3.3.3.3:443?sni=x.com&congestion_control=bbr#TUIC-SG
`

var vmessB64 = base64.StdEncoding.EncodeToString([]byte(
	`{"v":"2","ps":"US East","add":"4.4.4.4","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws","host":"h.com","path":"/ws","tls":"tls"}`))

func TestParseSubscriptionPlain(t *testing.T) {
	nodes := parseSubscription(sampleSub, 15)
	if len(nodes) != 6 {
		t.Fatalf("want 6 nodes, got %d", len(nodes))
	}
	types := []string{"VLESS", "HYSTERIA2", "VMESS", "TROJAN", "SS", "TUIC"}
	for i, n := range nodes {
		if n.Type != types[i] {
			t.Errorf("node %d: want type %s, got %s", i, types[i], n.Type)
		}
		if n.Tag == "" || n.Name == "" {
			t.Errorf("node %d: empty tag/name: %+v", i, n)
		}
	}
	if nodes[0].Name != "REALITY-GERMANY" {
		t.Errorf("vless name: got %q", nodes[0].Name)
	}
	if tls, ok := nodes[0].outbound["tls"].(map[string]any); !ok || tls["reality"] == nil {
		t.Errorf("vless reality block missing: %v", nodes[0].outbound)
	}
	if nodes[4].outbound["method"] != "aes-256-gcm" || nodes[4].outbound["password"] != "secretpass" {
		t.Errorf("ss parse: %v", nodes[4].outbound)
	}
}

func TestParseSubscriptionBase64(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(sampleSub))
	nodes := parseSubscription(enc, 3)
	if len(nodes) != 3 {
		t.Fatalf("base64 sub: want 3 nodes (limit), got %d", len(nodes))
	}
}

func TestGenerateConfig(t *testing.T) {
	nodes := parseSubscription(sampleSub, 15)
	cfg := generateConfig(nodes, defaultSettings())
	var m map[string]any
	if err := json.Unmarshal(cfg, &m); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	s := string(cfg)
	for _, want := range []string{`"proxy"`, `"geoip-ru"`, `"ru-bundle"`, `"clash_api"`, `"node-01"`, `"direct"`} {
		if !strings.Contains(s, want) {
			t.Errorf("config missing %s", want)
		}
	}
}
