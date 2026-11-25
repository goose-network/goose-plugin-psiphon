package psiphon

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"

	pub "github.com/goose-network/goose-plugin-api"
)

// dialRecorder is the shared recording core of the fake stack and route
// dialers below: one entry per dial, "network address".
type dialRecorder struct {
	mu    sync.Mutex
	dials []string
}

func (r *dialRecorder) record(network, address string) {
	r.mu.Lock()
	r.dials = append(r.dials, network+" "+address)
	r.mu.Unlock()
}

func (r *dialRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.dials...)
}

// fakeStackDialer is a pub.StackDialer answering Dial with a recorded pipe
// conn.
type fakeStackDialer struct{ rec *dialRecorder }

func (f fakeStackDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.rec.record(network, address)
	c1, c2 := net.Pipe()
	go func() { <-ctx.Done(); _ = c2.Close() }()
	return c1, nil
}

// fakeUpstreamDialer is a pub.UpstreamDialer answering DialUpstream with a
// recorded pipe conn.
type fakeUpstreamDialer struct{ rec *dialRecorder }

func (f fakeUpstreamDialer) DialUpstream(ctx context.Context, network, address string) (net.Conn, error) {
	f.rec.record(network, address)
	c1, c2 := net.Pipe()
	go func() { <-ctx.Done(); _ = c2.Close() }()
	return c1, nil
}

// TestDialerSelection verifies the fetch/tunnel dialer separation: tunnel
// dials ride the engine stack (the provider upstream is not even an input, so
// it can never reach them), while server-list fetches ride the injected engine
// route, falling back to the raw upstream proxy URL, then direct.
func TestDialerSelection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Tunnel dials: the stack carries them; a nil stack means direct (nil
	// dialer, tunnel-core's own kernel dialer).
	if d := tunnelCustomDialer(nil); d != nil {
		t.Fatal("tunnelCustomDialer(nil) must be nil (direct dial)")
	}
	stackRec := &dialRecorder{}
	d := tunnelCustomDialer(fakeStackDialer{stackRec})
	conn, err := d(ctx, "tcp", "192.0.2.10:443")
	if err != nil {
		t.Fatalf("tunnel dial through the stack: %v", err)
	}
	_ = conn.Close()
	if got := stackRec.recorded(); len(got) != 1 || got[0] != "tcp 192.0.2.10:443" {
		t.Fatalf("stack dialed %v, want one tcp dial to the server", got)
	}

	// Fetches: the injected route outranks the raw URL.
	routeRec := &dialRecorder{}
	d = fetchDialer(fakeUpstreamDialer{routeRec}, "socks5://127.0.0.1:7890")
	conn, err = d(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("fetch dial through the route: %v", err)
	}
	_ = conn.Close()
	if got := routeRec.recorded(); len(got) != 1 || got[0] != "tcp example.com:443" {
		t.Fatalf("route dialed %v, want one tcp fetch dial", got)
	}

	// No route, no raw URL: fetches dial directly (nil dialer).
	if d := fetchDialer(nil, ""); d != nil {
		t.Fatal("fetchDialer(nil, \"\") must be nil (direct fetch)")
	}
	// No route but a raw URL: a proxy fetch dialer is produced (exercised
	// against a live listener in TestRawProxyFetchDialerUsesProxy).
	if d := fetchDialer(nil, "socks5://127.0.0.1:7890"); d == nil {
		t.Fatal("fetchDialer(nil, rawURL) must produce a proxy dialer")
	}
}

// TestRawProxyFetchDialerUsesProxy verifies the raw-URL fetch dialer connects
// to the configured upstream proxy (not the target directly): the proxy
// listener accepts the connection, then refuses the SOCKS handshake, so the
// dial fails — but only after reaching the proxy.
func TestRawProxyFetchDialerUsesProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted.Add(1)
		_ = conn.Close() // refuse the proxy handshake
	}()

	d := fetchDialer(nil, "socks5://"+ln.Addr().String())
	if d == nil {
		t.Fatal("fetchDialer(nil, rawURL) returned nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := d(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected the refused proxy handshake to fail the dial")
	}
	if accepted.Load() == 0 {
		t.Fatal("fetch dialer did not connect to the raw upstream proxy")
	}
}

// TestStatusDialerDetails verifies the engine dialer bookkeeping in Status:
// which of the raw upstream_proxy URL, the engine route, and the engine
// stack carries which dial surface.
func TestStatusDialerDetails(t *testing.T) {
	p := &Provider{pinned: map[string]*serverTunnel{}}
	check := func(want map[string]bool) {
		t.Helper()
		for k, v := range want {
			if p.Status().Details[k] != v {
				t.Fatalf("%s = %v, want %v (details %v)", k, p.Status().Details[k], v, p.Status().Details)
			}
		}
	}

	// Bare provider: nothing routed.
	check(map[string]bool{"upstream_proxy": false, "engine_route": false, "engine_stack": false})

	// Raw URL: server-list fetches ride it; tunnel dials stay on the kernel
	// dialer (no stack injected yet).
	p.cfg.UpstreamProxy = "socks5://127.0.0.1:7890"
	check(map[string]bool{"upstream_proxy": true, "engine_route": false, "engine_stack": false})

	// Engine stack injected: it carries tunnel dials.
	p.stackDialer = fakeStackDialer{&dialRecorder{}}
	check(map[string]bool{"engine_stack": true})

	// Engine route injected: it carries the fetches; the stack still carries
	// tunnel dials (the route is fetch-only, never a tunnel dialer).
	p.upstream = fakeUpstreamDialer{&dialRecorder{}}
	check(map[string]bool{"engine_route": true, "engine_stack": true})
}

// encodeTestEntry builds a syntactically valid encoded server entry for the
// pinned-shape tests, the same encoding Config.TargetServerEntry consumes.
func encodeTestEntry(t *testing.T) string {
	t.Helper()
	encoded, err := protocol.EncodeServerEntry(&protocol.ServerEntry{
		IpAddress:       "192.0.2.10",
		WebServerPort:   "443",
		WebServerSecret: "test-secret",
		Region:          "TEST",
		Capabilities:    []string{"SSHAPI"},
	})
	if err != nil {
		t.Fatalf("EncodeServerEntry: %v", err)
	}
	return encoded
}

// TestSanitizeConfigStripsRuntimeFields verifies the sanitizer strips the
// runtime-owned fields the plugin sets per controller (a leaked
// TargetServerEntry would pin the general tunnel; leaked notice-file routing
// would swallow the server-list signal; a leaked data root would split
// state) and strips UpstreamProxyURL (the raw upstream is fetch-only, carried
// by the fetch dialer, never tunnel-core's config).
func TestSanitizeConfigStripsRuntimeFields(t *testing.T) {
	raw := `{
		"PropagationChannelId": "0000000000000000",
		"SponsorId": "0000000000000000",
		"DataRootDirectory": "/leaky",
		"MigrateDataStoreDirectory": "/leaky",
		"LocalSocksProxyPort": 1080,
		"EgressRegion": "DE",
		"NetworkID": "OTHER",
		"ClientPlatform": "Windows",
		"EstablishTunnelTimeoutSeconds": 1,
		"TargetServerEntry": "deadbeef",
		"DisableRemoteServerListFetcher": true,
		"DisableLocalSocksProxy": false,
		"EmitDiagnosticNotices": false,
		"UseNoticeFiles": {"RotatingFileSize": 1024},
		"UpstreamProxyUrl": "http://leaky"
	}`
	out, err := sanitizeConfig([]byte(raw))
	if err != nil {
		t.Fatalf("sanitizeConfig: %v", err)
	}
	cfg, err := psiphon.LoadConfig(out)
	if err != nil {
		t.Fatalf("LoadConfig(sanitized): %v", err)
	}
	if cfg.DataRootDirectory != "" || cfg.MigrateDataStoreDirectory != "" {
		t.Fatalf("data root leaked: %q %q", cfg.DataRootDirectory, cfg.MigrateDataStoreDirectory)
	}
	if cfg.TargetServerEntry != "" {
		t.Fatalf("TargetServerEntry leaked: %q", cfg.TargetServerEntry)
	}
	if cfg.DisableRemoteServerListFetcher != true {
		t.Fatal("an operator's DisableRemoteServerListFetcher must be respected, not stripped")
	}
	if cfg.EmitDiagnosticNotices {
		t.Fatal("EmitDiagnosticNotices must be stripped: the plugin owns notice routing")
	}
	if cfg.UseNoticeFiles != nil {
		t.Fatalf("UseNoticeFiles leaked: %v", cfg.UseNoticeFiles)
	}
	if cfg.EgressRegion != "" || cfg.NetworkID != "" || cfg.ClientPlatform != "" {
		t.Fatalf("identity fields leaked: %q %q %q", cfg.EgressRegion, cfg.NetworkID, cfg.ClientPlatform)
	}
	if cfg.EstablishTunnelTimeoutSeconds != nil {
		t.Fatalf("EstablishTunnelTimeoutSeconds leaked: %d", *cfg.EstablishTunnelTimeoutSeconds)
	}
	if cfg.UpstreamProxyURL != "" {
		t.Fatalf("UpstreamProxyURL must be stripped (fetch-only, never tunnel dials), got %q", cfg.UpstreamProxyURL)
	}
}

// TestNewTunnelCorePinnedShape verifies the pinned controller's config
// posture: pinned to the target entry, no list fetching / tactics / entry
// reporting, no local proxies, diagnostics on the hub.
func TestNewTunnelCorePinnedShape(t *testing.T) {
	encoded := encodeTestEntry(t)
	tc, err := newTunnelCore(defaultConfigJSON(), tunnelOptions{
		label:             "psiphon[192.0.2.10]",
		dataRootDirectory: t.TempDir(),
		targetServerEntry: encoded,
		establishTimeout:  2 * time.Minute,
	}, nil, nil)
	if err != nil {
		t.Fatalf("newTunnelCore(pinned): %v", err)
	}
	defer tc.stop()

	cfg := tc.config
	if cfg.TargetServerEntry != encoded {
		t.Fatalf("TargetServerEntry not pinned")
	}
	if !cfg.DisableRemoteServerListFetcher || !cfg.DisableTactics {
		t.Fatal("pinned controller must not fetch lists or tactics")
	}
	if cfg.DisableServerEntriesReporter == nil || !*cfg.DisableServerEntriesReporter {
		t.Fatal("pinned controller must not report entries")
	}
	if !cfg.DisableLocalSocksProxy || !cfg.DisableLocalHTTPProxy {
		t.Fatal("tunnels must not run local proxies: goose dials in memory")
	}
	if !cfg.EmitDiagnosticNotices || cfg.UseNoticeFiles != nil {
		t.Fatal("diagnostics must flow to the notice hub, not files")
	}
	if cfg.EstablishTunnelTimeoutSeconds == nil || *cfg.EstablishTunnelTimeoutSeconds != 120 {
		t.Fatalf("EstablishTunnelTimeoutSeconds = %v, want 120", cfg.EstablishTunnelTimeoutSeconds)
	}

	// Stopping before start is safe, and stop is idempotent.
	tc.stop()
	tc.stop()
	if !tc.stopped() {
		t.Fatal("stopped() after stop()")
	}
	// start after stop must not launch a Run loop.
	tc.start()
	select {
	case <-tc.ctx.Done():
	default:
		t.Fatal("ctx should be cancelled after stop")
	}
}

// TestNewTunnelCoreGeneralShape verifies the general tunnel keeps the list
// fetcher enabled (it is what auto-updates the servers the provider shows).
func TestNewTunnelCoreGeneralShape(t *testing.T) {
	tc, err := newTunnelCore(defaultConfigJSON(), tunnelOptions{
		label:             "psiphon",
		dataRootDirectory: t.TempDir(),
		establishTimeout:  90 * time.Second,
	}, nil, nil)
	if err != nil {
		t.Fatalf("newTunnelCore(general): %v", err)
	}
	defer tc.stop()

	if tc.config.DisableRemoteServerListFetcher {
		t.Fatal("general tunnel must keep the remote server list fetcher enabled")
	}
	if tc.config.TargetServerEntry != "" {
		t.Fatal("general tunnel must not be pinned")
	}
	if tc.config.EstablishTunnelTimeoutSeconds == nil || *tc.config.EstablishTunnelTimeoutSeconds != 90 {
		t.Fatalf("EstablishTunnelTimeoutSeconds = %v, want 90", tc.config.EstablishTunnelTimeoutSeconds)
	}
}

// TestOutboundFactory verifies the "psiphon" protocol factory parses the
// provider-emitted config shapes, and that dials fail fast without a live
// provider (the engine reports the error and falls back to other outbounds).
func TestOutboundFactory(t *testing.T) {
	general, err := New(map[string]any{"id": "psiphon", "tunnel": "psiphon"})
	if err != nil {
		t.Fatalf("New(general): %v", err)
	}
	if general.Protocol() != "psiphon" || general.ID() != "psiphon" || general.Address() != "" {
		t.Fatalf("general outbound: %q %q %q", general.ID(), general.Protocol(), general.Address())
	}

	server, err := New(map[string]any{
		"id":      "psiphon-192.0.2.10:443",
		"tunnel":  "psiphon",
		"server":  "192.0.2.10:443",
		"address": "192.0.2.10:443",
		"region":  "TEST",
	})
	if err != nil {
		t.Fatalf("New(server): %v", err)
	}
	if server.Address() != "192.0.2.10:443" {
		t.Fatalf("server outbound address = %q", server.Address())
	}

	// Defaults for a minimal hand-written config.
	bare, err := New(map[string]any{})
	if err != nil {
		t.Fatalf("New(bare): %v", err)
	}
	if bare.ID() != "psiphon" || bare.Protocol() != "psiphon" {
		t.Fatalf("bare outbound: %q %q", bare.ID(), bare.Protocol())
	}

	// UDP is refused without touching the registry.
	if _, err := bare.DialContext(context.Background(), pub.NetworkUDP, "example.com:53"); err == nil {
		t.Fatal("UDP dial should fail: Psiphon tunnels TCP only")
	}

	// No live provider registered under the tunnel id: fail fast with a
	// diagnosable error instead of hanging.
	if _, err := bare.DialContext(context.Background(), pub.NetworkTCP, "example.com:80"); err == nil {
		t.Fatal("dial without a live provider should fail")
	}
}

// TestOutboundFactoryNeedsKnownServer verifies a per-server dial with a live
// provider errors for a server absent from the provider's scan cache rather
// than dialing blind.
func TestOutboundFactoryNeedsKnownServer(t *testing.T) {
	p := &Provider{
		cfg: providerConfig{OutboundID: "psiphon-test-needs-known"},
		servers: map[string]serverInfo{
			"192.0.2.10:443": {IP: "192.0.2.10", Address: "192.0.2.10:443", Encoded: encodeTestEntry(t)},
		},
		pinned: map[string]*serverTunnel{},
	}
	registerLiveProvider(p)
	defer unregisterLiveProvider(p)

	known, err := New(map[string]any{"id": "k", "tunnel": p.cfg.OutboundID, "server": "192.0.2.10:443"})
	if err != nil {
		t.Fatalf("New(known): %v", err)
	}
	// The dial reaches tunnel startup and fails there (no datastore in this
	// test); what matters is it gets past the scan-cache check. The error
	// must not be "not in the current list".
	_, dialErr := known.DialContext(context.Background(), pub.NetworkTCP, "example.com:80")
	if dialErr != nil && dialErr.Error() == "psiphon: server 192.0.2.10:443 is not in the current list" {
		t.Fatalf("known server rejected: %v", dialErr)
	}

	unknown, err := New(map[string]any{"id": "u", "tunnel": p.cfg.OutboundID, "server": "192.0.2.99:443"})
	if err != nil {
		t.Fatalf("New(unknown): %v", err)
	}
	if _, err := unknown.DialContext(context.Background(), pub.NetworkTCP, "example.com:80"); err == nil {
		t.Fatal("dial to a server outside the list should fail")
	}
}

// TestNoticeHubFanout verifies the hub delivers every notice to every
// subscriber and that unsubscribed callbacks stop receiving.
func TestNoticeHubFanout(t *testing.T) {
	var got []string
	unsub := hub.subscribe(func(n notice) { got = append(got, n.Type) })
	_ = hub.subscribe(func(n notice) { got = append(got, n.Type) })

	hub.dispatch([]byte(`{"noticeType":"Tunnels","data":{"count":1}}`))
	if len(got) != 2 {
		t.Fatalf("fanout delivered %d, want 2", len(got))
	}

	got = nil
	unsub()
	hub.dispatch([]byte(`{"noticeType":"Tunnels","data":{"count":1}}`))
	if len(got) != 1 {
		t.Fatalf("after unsubscribe delivered %d, want 1", len(got))
	}

	// Malformed events are dropped, not propagated.
	got = nil
	hub.dispatch([]byte(`{not json`))
	hub.dispatch([]byte(`{"data":{}}`)) // no noticeType
	if len(got) != 0 {
		t.Fatalf("malformed notices delivered %d, want 0", len(got))
	}
}

// TestHandleNoticeSignalsWatch verifies the two notice types the provider
// reacts to signal the engine: tunnel up and server-list download.
func TestHandleNoticeSignalsWatch(t *testing.T) {
	p := &Provider{watchCh: make(chan struct{}, 1)}

	p.handleNotice(notice{Type: "Tunnels", Data: map[string]any{"count": float64(1)}})
	select {
	case <-p.Watch():
	default:
		t.Fatal("Tunnels(count>0) should signal Watch")
	}

	p.handleNotice(notice{Type: "Tunnels", Data: map[string]any{"count": float64(0)}})
	select {
	case <-p.Watch():
		t.Fatal("Tunnels(count=0) should not signal Watch")
	default:
	}

	p.handleNotice(notice{Type: "RemoteServerListResourceDownloaded"})
	select {
	case <-p.Watch():
	default:
		t.Fatal("RemoteServerListResourceDownloaded should signal Watch")
	}
}

// TestParseConfigDefaults verifies the zero-config posture: defaults for
// outbound id, establish timeout, and the data dir.
func TestParseConfigDefaults(t *testing.T) {
	pc, err := parseConfig(map[string]any{})
	if err != nil {
		t.Fatalf("parseConfig(empty): %v", err)
	}
	if pc.OutboundID != "psiphon" {
		t.Fatalf("OutboundID = %q", pc.OutboundID)
	}
	if pc.EstablishTimeoutSeconds != 120 {
		t.Fatalf("EstablishTimeoutSeconds = %d", pc.EstablishTimeoutSeconds)
	}
	if pc.DataDir != "psiphon-data" {
		t.Fatalf("DataDir = %q", pc.DataDir)
	}

	// The engine-injected dialer keys must be stripped before the JSON
	// round-trip, and the caller's map must not be mutated.
	nonMarshalable := func() {} // funcs break json.Marshal
	in := map[string]any{
		pub.StackDialerKey:    nonMarshalable,
		pub.UpstreamDialerKey: nonMarshalable,
	}
	if _, err := parseConfig(in); err != nil {
		t.Fatalf("parseConfig with injected dialers: %v", err)
	}
	if _, still := in[pub.StackDialerKey]; !still {
		t.Fatal("parseConfig must not mutate the caller's config map")
	}
}

// TestStatusReport verifies the provider's self-assessment: phases from the
// general tunnel's lifecycle, server-list bookkeeping, and the pinned-tunnel
// summary — the fields the engine's provider status endpoint surfaces.
func TestStatusReport(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "psiphon", EstablishTimeoutSeconds: 30},
		dataDir: "/tmp/psiphon-status-test",
		servers: map[string]serverInfo{"1.2.3.4:443": {}, "5.6.7.8:443": {}},
		pinned:  map[string]*serverTunnel{},
		watchCh: make(chan struct{}, 1),
	}

	st := p.Status()
	if st.State != "starting" {
		t.Errorf("nil-tunnel status state = %q, want %q", st.State, "starting")
	}

	p.main = &tunnelCore{}
	st = p.Status()
	if st.State != "establishing" {
		t.Errorf("fresh-tunnel status state = %q, want %q", st.State, "establishing")
	}
	if st.Message == "" {
		t.Error("establishing status should carry a message")
	}

	p.main.established.Store(true)
	st = p.Status()
	if st.State != "running" {
		t.Errorf("established status state = %q, want %q", st.State, "running")
	}
	if st.Details["servers_in_list"] != 2 {
		t.Errorf("servers_in_list = %v, want 2", st.Details["servers_in_list"])
	}
	if st.Details["last_list_download"] != "never" {
		t.Errorf("last_list_download = %v, want \"never\"", st.Details["last_list_download"])
	}
	if _, ok := st.Details["pinned_tunnels"]; ok {
		t.Error("pinned_tunnels present with none running")
	}

	// A pinned tunnel with an open connection is summarized.
	stp := &serverTunnel{addr: "1.2.3.4:443"}
	stp.open.Add(2)
	p.pinned["1.2.3.4:443"] = stp
	st = p.Status()
	if pins, ok := st.Details["pinned_tunnels"].([]string); !ok || len(pins) != 1 || pins[0] != "1.2.3.4:443" {
		t.Errorf("pinned_tunnels = %v, want [1.2.3.4:443]", st.Details["pinned_tunnels"])
	}
	if st.Details["open_connections"] != 2 {
		t.Errorf("open_connections = %v, want 2", st.Details["open_connections"])
	}

	// A list download timestamps itself.
	p.handleNotice(notice{Type: "RemoteServerListResourceDownloaded"})
	st = p.Status()
	if st.Details["last_list_download"] == "never" {
		t.Error("last_list_download still \"never\" after a download notice")
	}
}

// TestOutboundsOmitsGenericTunnel verifies the provider emits no generic
// main-tunnel outbound, even once the main tunnel is established: which
// server such a dial exits from is tunnel-core's per-connection choice, so
// the engine could never attribute an exit IP, region or latency sample to a
// server it cannot see. Every pinnable server keeps its own record.
func TestOutboundsOmitsGenericTunnel(t *testing.T) {
	root := t.TempDir()
	// OpenDataStore needs its directory tree to exist; the bolt file itself
	// it creates.
	storeDir := filepath.Join(root, "ca.psiphon.PsiphonTunnel.tunnel-core", "datastore")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := psiphon.OpenDataStore(&psiphon.Config{DataRootDirectory: root}); err != nil {
		t.Fatalf("OpenDataStore: %v", err)
	}
	defer psiphon.CloseDataStore()

	p := &Provider{
		cfg:     providerConfig{OutboundID: "psiphon"},
		dataDir: root,
		servers: map[string]serverInfo{},
		pinned:  map[string]*serverTunnel{},
		watchCh: make(chan struct{}, 1),
		main:    &tunnelCore{},
	}
	p.main.established.Store(true) // the old gate for the generic emission

	out, err := p.Outbounds(context.Background())
	if err != nil {
		t.Fatalf("Outbounds: %v", err)
	}
	for _, o := range out {
		if o.ID == "psiphon" {
			t.Errorf("generic tunnel outbound %q emitted with config %v", o.ID, o.Config)
		}
	}
	if len(out) != 0 {
		t.Errorf("outbounds with an empty datastore = %v, want none", out)
	}
}

// TestServerInfoKey verifies the endpoint identity used for outbound IDs and
// the pin-source map: ip:port when the entry has a web server port, falling
// back to the bare IP otherwise.
func TestServerInfoKey(t *testing.T) {
	if k := (serverInfo{IP: "1.2.3.4", Address: "1.2.3.4:443"}).key(); k != "1.2.3.4:443" {
		t.Errorf("key = %q, want 1.2.3.4:443", k)
	}
	if k := (serverInfo{IP: "1.2.3.4"}).key(); k != "1.2.3.4" {
		t.Errorf("fallback key = %q, want 1.2.3.4", k)
	}
}

// TestOutboundsIDsCarryAddress verifies every per-server outbound ID carries
// the server's ip:port literally, the "id" config key equals the ID, and
// "server" matches the pin-source map key the dial path looks up. Distinct
// endpoints get distinct IDs.
func TestOutboundsIDsCarryAddress(t *testing.T) {
	root := t.TempDir()
	storeDir := filepath.Join(root, "ca.psiphon.PsiphonTunnel.tunnel-core", "datastore")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := psiphon.OpenDataStore(&psiphon.Config{DataRootDirectory: root}); err != nil {
		t.Fatalf("OpenDataStore: %v", err)
	}
	defer psiphon.CloseDataStore()

	store := func(ip, port, secret string) {
		t.Helper()
		data, err := json.Marshal(&protocol.ServerEntry{
			IpAddress:       ip,
			WebServerPort:   port,
			WebServerSecret: secret,
			Region:          "TEST",
			Capabilities:    []string{protocol.CAPABILITY_SSH_API_REQUESTS},
		})
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		var fields protocol.ServerEntryFields
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatalf("unmarshal fields: %v", err)
		}
		fields.SetLocalSource(protocol.SERVER_ENTRY_SOURCE_EMBEDDED)
		fields.SetLocalTimestamp(time.Now().UTC().Format(time.RFC3339))
		if err := psiphon.StoreServerEntry(fields, true); err != nil {
			t.Fatalf("StoreServerEntry: %v", err)
		}
	}
	store("192.0.2.10", "443", "secret-a")
	store("192.0.2.20", "8443", "secret-b")

	p := &Provider{
		cfg:     providerConfig{OutboundID: "psiphon"},
		dataDir: root,
		servers: map[string]serverInfo{},
		pinned:  map[string]*serverTunnel{},
		watchCh: make(chan struct{}, 1),
		main:    &tunnelCore{},
	}
	out, err := p.Outbounds(context.Background())
	if err != nil {
		t.Fatalf("Outbounds: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("outbounds = %d, want 2 (%v)", len(out), out)
	}
	byID := map[string]pub.OutboundConfig{}
	for _, o := range out {
		byID[o.ID] = o
	}
	for _, addr := range []string{"192.0.2.10:443", "192.0.2.20:8443"} {
		id := "psiphon-" + addr
		o, ok := byID[id]
		if !ok {
			t.Fatalf("missing outbound ID %q (got %v)", id, byID)
		}
		if o.Config["id"] != id {
			t.Errorf("config id = %v, want %q", o.Config["id"], id)
		}
		if o.Config["server"] != addr {
			t.Errorf("config server = %v, want %q", o.Config["server"], addr)
		}
		if o.Config["address"] != addr {
			t.Errorf("config address = %v, want %q", o.Config["address"], addr)
		}
		// The pin-source map is keyed by the same endpoint the ID carries, so
		// the dial path (serverTunnelState) finds it.
		if _, ok := p.servers[addr]; !ok {
			t.Errorf("pin-source map missing key %q", addr)
		}
	}
}

// TestServerTunnelStateRefusesAfterClose pins the Close ordering: a dial that
// already passed lookupLiveProvider must not be handed pinned state, because
// Close has drained p.pinned and nothing would ever stop what it starts. The
// closed check must also precede the servers lookup, so no fresh state is
// created from the last scan after Close.
func TestServerTunnelStateRefusesAfterClose(t *testing.T) {
	p := &Provider{
		closed:  true,
		servers: map[string]serverInfo{"1.2.3.4:443": {IP: "1.2.3.4", Address: "1.2.3.4:443"}},
		pinned:  map[string]*serverTunnel{},
	}
	if _, err := p.serverTunnelState("1.2.3.4:443"); err == nil {
		t.Error("serverTunnelState handed out state on a closed provider")
	}
}

// TestTunnelForServerRefusesDeadState covers the reaper's window: state that
// was stopped and dropped from p.pinned while a dial still held a reference
// must not sprout a controller nobody would ever reap or close again. The
// dialer's retry gets fresh state from serverTunnelState instead.
func TestTunnelForServerRefusesDeadState(t *testing.T) {
	p := &Provider{cfg: providerConfig{OutboundID: "psiphon"}}
	st := &serverTunnel{addr: "1.2.3.4:443"}
	st.stop()
	_, err := p.tunnelForServer(st)
	if err == nil || !strings.Contains(err.Error(), "retired") {
		t.Errorf("tunnelForServer on retired state = %v, want the retired-state error", err)
	}
}
