package locking

import "sync"

// Registry serializes operations that address the same remote singleton while
// allowing independent resource keys to proceed concurrently.
type Registry struct {
	mu    sync.Mutex
	locks map[string]*keyLock
}

type keyLock struct {
	mu   sync.Mutex
	refs int
}

// NewRegistry creates an empty keyed mutex registry.
func NewRegistry() *Registry {
	return &Registry{locks: make(map[string]*keyLock)}
}

// Lock acquires the mutex for key and returns an idempotent unlock function.
func (r *Registry) Lock(key string) func() {
	r.mu.Lock()
	lock := r.locks[key]
	if lock == nil {
		lock = &keyLock{}
		r.locks[key] = lock
	}
	lock.refs++
	r.mu.Unlock()

	lock.mu.Lock()
	var once sync.Once
	return func() {
		once.Do(func() {
			lock.mu.Unlock()
			r.mu.Lock()
			lock.refs--
			if lock.refs == 0 {
				delete(r.locks, key)
			}
			r.mu.Unlock()
		})
	}
}
