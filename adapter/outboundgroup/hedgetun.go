package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"hedgetun/hedgeconn"
)

// hedgeTunMaxPaths is how many members a tunnel can dial (connection ids
// are one byte); the server accepts server_opts.max_paths of them.
const hedgeTunMaxPaths = 255

var errHedgeTunUDP = errors.New("hedgetun carries TCP only")

// HedgeTun is a hedgetun client as a proxy group: one tunnel to a hedgetun
// server with a connection through every member (the available set). The
// best sched.max_selected_paths members by round trip (the workset, default
// 8) carry traffic, and the active set is chosen within the workset. Every
// connection routed to the group becomes a tunnel session
// (third_party/hedgetun, hedgeconn).
type HedgeTun struct {
	*GroupBase
	state *hedgeTunState
}

// hedgeTunState is the running part. It is apart from HedgeTun so that its
// goroutines do not keep the group reachable: on a config reload mihomo
// drops the old group without closing it, and the group's finalizer then
// stops the tunnel, like outbound.NewAutoCloseProxyAdapter does for
// proxies. Connections hold the group, so they keep the tunnel.
type hedgeTunState struct {
	name   string
	gb     *GroupBase
	cfg    *hedgeconn.Config
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	client *hedgeconn.Client
	paths  []string // the members the tunnel dials, fixed when it starts
}

func (h *HedgeTun) Now() string {
	return ""
}

// DialContext implements C.ProxyAdapter
func (h *HedgeTun) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	cl, err := h.state.start()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name(), err)
	}
	c, err := cl.Dial(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name(), err)
	}
	return outbound.NewConn(N.NewRefConn(c, h), h), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (h *HedgeTun) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return nil, fmt.Errorf("%s: %w", h.Name(), errHedgeTunUDP)
}

// SupportUDP implements C.ProxyAdapter
func (h *HedgeTun) SupportUDP() bool {
	return false
}

// IsL3Protocol implements C.ProxyAdapter
func (h *HedgeTun) IsL3Protocol(metadata *C.Metadata) bool {
	return false
}

// Unwrap implements C.ProxyAdapter: sessions go over several members at
// once, so there is no single one to extract.
func (h *HedgeTun) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return nil
}

// MarshalJSON implements C.ProxyAdapter
func (h *HedgeTun) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range h.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":          h.Type().String(),
		"now":           h.Now(),
		"all":           all,
		"paths":         h.state.dialed(),
		"hidden":        h.Hidden(),
		"icon":          h.Icon(),
		"emptyFallback": h.EmptyFallback().Name(),
	})
}

// Close implements C.ProxyAdapter
func (h *HedgeTun) Close() error {
	h.state.close()
	return nil
}

func (h *HedgeTun) Providers() []P.ProxyProvider {
	return h.providers
}

func (h *HedgeTun) Proxies() []C.Proxy {
	return h.GetProxies(false)
}

// start starts the tunnel over the current members if it is not running.
func (s *hedgeTunState) start() (*hedgeconn.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	if s.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	names := s.members()
	if len(names) == 0 {
		return nil, errors.New("no members yet")
	}
	paths := make([]hedgeconn.Path, len(names))
	for i, name := range names {
		paths[i] = hedgeconn.Path{Name: name, Dial: s.dialer(name)}
	}
	cl, err := hedgeconn.Start(s.ctx, s.cfg, paths)
	if err != nil {
		return nil, err
	}
	log.Infoln("[%s] hedgetun to %s over %d members: %v", s.name, s.cfg.Server(), len(names), names)
	s.client, s.paths = cl, names
	return cl, nil
}

// warm starts the tunnel as soon as the providers have members, so the
// first connection does not wait for its handshakes.
func (s *hedgeTunState) warm() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if _, err := s.start(); err == nil || s.ctx.Err() != nil {
			return
		}
		select {
		case <-t.C:
		case <-s.ctx.Done():
			return
		}
	}
}

// members are the relays: the group's proxies, one per server address.
// COMPATIBLE (an empty group's fallback) is no relay.
func (s *hedgeTunState) members() []string {
	var names []string
	seen := map[string]bool{}
	for _, p := range s.gb.GetProxies(false) {
		if p.Type() == C.Compatible {
			continue
		}
		if addr := p.Addr(); addr != "" {
			if seen[addr] {
				continue
			}
			seen[addr] = true
		}
		names = append(names, p.Name())
		if len(names) == hedgeTunMaxPaths {
			break
		}
	}
	return names
}

// dialer connects to the hedgetun server through the member named name, as
// it is now: a provider update replaces the proxy under the same name.
func (s *hedgeTunState) dialer(name string) func(ctx context.Context, server string) (net.Conn, error) {
	return func(ctx context.Context, server string) (net.Conn, error) {
		var proxy C.Proxy
		for _, p := range s.gb.GetProxies(false) {
			if p.Name() == name {
				proxy = p
				break
			}
		}
		if proxy == nil {
			return nil, fmt.Errorf("%s is no longer a member", name)
		}
		host, port, err := net.SplitHostPort(server)
		if err != nil {
			return nil, err
		}
		portNum, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, err
		}
		metadata := &C.Metadata{NetWork: C.TCP, DstPort: uint16(portNum)}
		if ip, err := netip.ParseAddr(host); err == nil {
			metadata.DstIP = ip
		} else {
			metadata.Host = host
		}
		return proxy.DialContext(ctx, metadata)
	}
}

func (s *hedgeTunState) dialed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.paths...)
}

func (s *hedgeTunState) close() {
	s.cancel()
	s.mu.Lock()
	cl := s.client
	s.client = nil
	s.mu.Unlock()
	if cl != nil {
		log.Debugln("[%s] closing hedgetun", s.name)
		_ = cl.Close()
	}
}

func NewHedgeTun(option GroupCommonOption, config map[string]any, emptyFallback C.Proxy, providers []P.ProxyProvider) (*HedgeTun, error) {
	cfg, err := hedgeconn.ParseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", option.Name, err)
	}
	gb := NewGroupBase(GroupBaseOption{
		Name:           option.Name,
		Type:           C.HedgeTun,
		Hidden:         option.Hidden,
		Icon:           option.Icon,
		Filter:         option.Filter,
		ExcludeFilter:  option.ExcludeFilter,
		ExcludeType:    option.ExcludeType,
		TestTimeout:    option.TestTimeout,
		MaxFailedTimes: option.MaxFailedTimes,
		EmptyFallback:  emptyFallback,
		Providers:      providers,
	})
	ctx, cancel := context.WithCancel(context.Background())
	state := &hedgeTunState{name: option.Name, gb: gb, cfg: cfg, ctx: ctx, cancel: cancel}
	h := &HedgeTun{GroupBase: gb, state: state}
	// Stopping waits for the tunnel's goroutines; keep that off the
	// runtime's single finalizer goroutine.
	runtime.SetFinalizer(h, func(h *HedgeTun) { go h.state.close() })
	go state.warm()
	return h, nil
}
