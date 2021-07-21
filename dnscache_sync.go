package dnscache

import (
	"context"
	"net"
	"sync"
	"time"
)

type ResolverSync struct {
	// Timeout defines the maximum allowed time allowed for a lookup.
	Timeout time.Duration

	// Resolver is used to perform actual DNS lookup. If nil,
	// net.DefaultResolver is used instead.
	Resolver DNSResolver

	//once sync.Once
	//	mu    sync.RWMutex
	//	cache map[string]*cacheEntry
	cache sync.Map

	// OnCacheMiss is executed if the host or address is not included in
	// the cache and the default lookup is executed.
	OnCacheMiss func()
}

// LookupAddr performs a reverse lookup for the given address, returning a list
// of names mapping to that address.
func (rs *ResolverSync) LookupAddr(ctx context.Context, addr string) (names []string, err error) {
	return rs.lookup(ctx, "r"+addr)
}

// LookupHost looks up the given host using the local resolver. It returns a
// slice of that host's addresses.
func (rs *ResolverSync) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	return rs.lookup(ctx, "h"+host)
}

func (rs *ResolverSync) refreshRecords(clearUnused bool, persistOnFailure bool) {
	del := make([]string, 0)
	update := make([]string, 0)

	rs.cache.Range(func(key, value interface{}) bool {
		if value.(*cacheEntry).used {
			update = append(del, key.(string))
		} else if clearUnused {
			del = append(del, key.(string))
		}
		return true
	})

	for _, v := range del {
		rs.cache.Delete(v)
	}

	for _, v := range update {
		rs.update(context.Background(), v, false, persistOnFailure)
	}
}

func (rs *ResolverSync) Refresh(clearUnused bool) {
	rs.refreshRecords(clearUnused, false)
}

func (rs *ResolverSync) RefreshWithOptions(options ResolverRefreshOptions) {
	rs.refreshRecords(options.ClearUnused, options.PersistOnFailure)
}

func (rs *ResolverSync) lookup(ctx context.Context, key string) (rrs []string, err error) {
	var found bool
	rrs, err, found = rs.load(key)
	if !found {
		if rs.OnCacheMiss != nil {
			rs.OnCacheMiss()
		}

		rrs, err = rs.update(ctx, key, true, false)
	}
	return
}

func (rs *ResolverSync) update(ctx context.Context, key string, used bool, persistOnFailure bool) (rrs []string, err error) {
	c := lookupGroup.DoChan(key, rs.lookupFunc(key))

	select {
	case <-ctx.Done():
		err := ctx.Err()
		if err == context.DeadlineExceeded {
			lookupGroup.Forget(key)
		}
	case res := <-c:
		if res.Shared {
			// We had concurrent lookups, check if the cache is already updated
			// by a friend.
			var found bool
			rrs, err, found = rs.load(key)
			if found {
				return
			}
		}
		err = res.Err
		if err == nil {
			rrs, _ = res.Val.([]string)
		}

		if err != nil && persistOnFailure {
			var found bool
			rrs, err, found = rs.load(key)
			if found {
				return
			}
		}

		rs.storeLocked(key, rrs, used, err)
	}
	return
}

func (rs *ResolverSync) lookupFunc(key string) func() (interface{}, error) {
	if len(key) == 0 {
		panic("lookupFunc with empty key")
	}

	var resolver DNSResolver = net.DefaultResolver
	if rs.Resolver != nil {
		resolver = rs.Resolver
	}

	switch key[0] {
	case 'h':
		return func() (interface{}, error) {
			ctx, cancel := rs.getCtx()
			defer cancel()
			return resolver.LookupHost(ctx, key[1:])
		}
	case 'r':
		return func() (interface{}, error) {
			ctx, cancel := rs.getCtx()
			defer cancel()
			return resolver.LookupAddr(ctx, key[1:])
		}
	default:
		panic("lookupFunc invalid key type: " + key)
	}

}

func (rs *ResolverSync) getCtx() (ctx context.Context, cancel context.CancelFunc) {
	ctx = context.Background()
	if rs.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, rs.Timeout)
	} else {
		cancel = func() {}
	}
	return
}

func (rs *ResolverSync) load(key string) (rrs []string, err error, found bool) {
	value, ok := rs.cache.Load(key)
	if !ok {
		return
	}

	rrs = value.(*cacheEntry).rrs
	err = value.(*cacheEntry).err
	rs.cache.Store(key, &cacheEntry{rrs: rrs, err: err, used: true})
	return rrs, err, true
}

func (rs *ResolverSync) storeLocked(key string, rrs []string, used bool, err error) {
	if _, ok := rs.cache.Load(key); ok {
		rs.cache.Store(key, &cacheEntry{rrs: rrs, err: err, used: used})
		return
	}
	rs.cache.Store(key, &cacheEntry{rrs: rrs, err: err, used: used})
}
