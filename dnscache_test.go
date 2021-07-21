package dnscache

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestResolver_LookupHost(t *testing.T) {
	r := &Resolver{}
	var cacheMiss bool
	r.OnCacheMiss = func() {
		cacheMiss = true
	}
	hosts := []string{"google.com", "google.com.", "netflix.com"}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			for _, wantMiss := range []bool{true, false, false} {
				cacheMiss = false
				addrs, err := r.LookupHost(context.Background(), host)
				if err != nil {
					t.Fatal(err)
				}
				if len(addrs) == 0 {
					t.Error("got no record")
				}
				for _, addr := range addrs {
					if net.ParseIP(addr) == nil {
						t.Errorf("got %q; want a literal IP address", addr)
					}
				}
				if wantMiss != cacheMiss {
					t.Errorf("got cache miss=%v, want %v", cacheMiss, wantMiss)
				}
			}
		})
	}
}

func TestClearCache(t *testing.T) {
	r := &Resolver{}
	_, _ = r.LookupHost(context.Background(), "google.com")
	if e := r.cache["hgoogle.com"]; e != nil && !e.used {
		t.Error("cache entry used flag is false, want true")
	}
	r.Refresh(true)
	if e := r.cache["hgoogle.com"]; e != nil && e.used {
		t.Error("cache entry used flag is true, want false")
	}
	r.Refresh(true)
	if e := r.cache["hgoogle.com"]; e != nil {
		t.Error("cache entry is not cleared")
	}

	options := ResolverRefreshOptions{}
	options.ClearUnused = true
	options.PersistOnFailure = false
	_, _ = r.LookupHost(context.Background(), "google.com")
	if e := r.cache["hgoogle.com"]; e != nil && !e.used {
		t.Error("cache entry used flag is false, want true")
	}
	r.RefreshWithOptions(options)
	if e := r.cache["hgoogle.com"]; e != nil && e.used {
		t.Error("cache entry used flag is true, want false")
	}
	r.RefreshWithOptions(options)
	if e := r.cache["hgoogle.com"]; e != nil {
		t.Error("cache entry is not cleared")
	}

	options.ClearUnused = false
	options.PersistOnFailure = true
	br := &Resolver{}
	br.Resolver = BadResolver{}

	_, _ = br.LookupHost(context.Background(), "google.com")
	br.Resolver = BadResolver{choke: true}
	br.RefreshWithOptions(options)
	if len(br.cache["hgoogle.com"].rrs) == 0 {
		t.Error("cache entry is cleared")
	}

}

func TestRaceOnDelete(t *testing.T) {
	r := &Resolver{}
	ls := make(chan bool)
	rs := make(chan bool)

	go func() {
		for {
			select {
			case <-ls:
				return
			default:
				r.LookupHost(context.Background(), "google.com")
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-rs:
				return
			default:
				r.Refresh(true)
				time.Sleep(time.Millisecond)
			}
		}
	}()

	time.Sleep(1 * time.Second)

	ls <- true
	rs <- true

}

func TestResolverSync_LookupHost(t *testing.T) {
	r := &ResolverSync{}
	var cacheMiss bool
	r.OnCacheMiss = func() {
		cacheMiss = true
	}
	hosts := []string{"google.com", "google.com.", "netflix.com"}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			for _, wantMiss := range []bool{true, false, false} {
				cacheMiss = false
				addrs, err := r.LookupHost(context.Background(), host)
				if err != nil {
					t.Fatal(err)
				}
				if len(addrs) == 0 {
					t.Error("got no record")
				}
				for _, addr := range addrs {
					if net.ParseIP(addr) == nil {
						t.Errorf("got %q; want a literal IP address", addr)
					}
				}
				if wantMiss != cacheMiss {
					t.Errorf("got cache miss=%v, want %v", cacheMiss, wantMiss)
				}
			}
		})
	}
}

func TestSyncClearCache(t *testing.T) {
	r := &ResolverSync{}
	_, _ = r.LookupHost(context.Background(), "google.com")
	if e, ok := r.cache.Load("hgoogle.com"); ok && !e.(*cacheEntry).used {
		t.Error("cache entry used flag is false, want true")
	}
	r.Refresh(true)
	if e, ok := r.cache.Load("hgoogle.com"); !ok && e.(*cacheEntry).used {
		t.Error("cache entry used flag is true, want false")
	}
	r.Refresh(true)
	if _, ok := r.cache.Load("hgoogle.com"); ok {
		t.Error("cache entry is not cleared")
	}

	options := ResolverRefreshOptions{}
	options.ClearUnused = true
	options.PersistOnFailure = false
	_, _ = r.LookupHost(context.Background(), "google.com")
	if e, ok := r.cache.Load("hgoogle.com"); ok && !e.(*cacheEntry).used {
		t.Error("cache entry used flag is false, want true")
	}
	r.RefreshWithOptions(options)
	if e, ok := r.cache.Load("hgoogle.com"); !ok && e.(*cacheEntry).used {
		t.Error("cache entry used flag is true, want false")
	}
	r.RefreshWithOptions(options)
	if _, ok := r.cache.Load("hgoogle.com"); ok {
		t.Error("cache entry is not cleared")
	}

	options.ClearUnused = false
	options.PersistOnFailure = true
	br := &Resolver{}
	br.Resolver = BadResolver{}

	_, _ = br.LookupHost(context.Background(), "google.com")
	br.Resolver = BadResolver{choke: true}
	br.RefreshWithOptions(options)
	if len(br.cache["hgoogle.com"].rrs) == 0 {
		t.Error("cache entry is cleared")
	}

}
