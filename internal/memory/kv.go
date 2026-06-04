// Package memory provides isobox's tier-3 "structured long-term memory": an
// embedded, on-disk key/value store an agent can write once and recall across
// sessions. Each tenant gets ONE bbolt file (<dir>/<tenant>.bolt). bbolt is
// pure-Go, so the single static binary is preserved, and it takes an exclusive
// flock per file — combined with a process-wide sync.Map of open handles, that
// guarantees exactly one *bbolt.DB per tenant in-process (concurrency-safe:
// one writer, many readers).
//
// SECURITY MODEL (the load-bearing invariant): the `tenant` argument is the
// SERVER-DERIVED tenant id (sha256(apiKey) hex). It is NEVER taken from a
// request field. This package re-validates it as a 64-char lowercase hex string
// before it is ever joined into a filesystem path — the same defence-in-depth
// posture as session.safePath. A caller can therefore never escape its own
// .bolt file no matter what it sends.
//
// STORAGE LAYOUT (per tenant file):
//
//	bucket "ns:<namespace>"  key = opaque userKey     val = gob{record}
//	bucket "_meta"           key "usedBytes"/"keyCount" = 8-byte big-endian
//	bucket "_ttl"            key = ts||nsLen||ns||userKey (see ttlKey) val = {}
//
// Every mutation (Put/Delete/sweep) does the full read-modify-write — touch the
// ns bucket, the _ttl index, AND the _meta counters — inside ONE db.Update
// transaction, so quota accounting and the TTL index can never drift from the
// data. Expiry is lazy on read (Get/List treat an expired-but-present record as
// absent) and physically reclaimed by SweepExpired.
package memory

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Quotas: per-tenant caps enforced inside the same write transaction.
const (
	MaxBytesPerTenant = 10 << 20 // 10 MiB of (encoded value + key) bytes
	MaxKeysPerTenant  = 10_000   // 10k keys
	MaxNamespaceLen   = 128      // bound on namespace (becomes a bucket name)
	MaxKeyLen         = 512      // bound on an opaque user key
	MaxValueLen       = 8 << 20  // single value cap (well under the tenant cap)
)

// Errors are KV-prefixed to coexist with the volume manager in this same
// package (which already defines ErrKVNotFound/ErrKVQuota with volume semantics).
var (
	ErrKVNotFound  = errors.New("memory: key not found")
	ErrKVQuota     = errors.New("memory: tenant quota exceeded")
	ErrKVTenant    = errors.New("memory: invalid tenant id")
	ErrKVNamespace = errors.New("memory: invalid namespace")
	ErrKVKey       = errors.New("memory: invalid key")
	ErrKVValueSize = errors.New("memory: value too large")
	ErrKVClosed    = errors.New("memory: store closed")
)

// Bucket names and the fixed _meta keys. The "ns:" prefix namespaces user
// buckets away from the two reserved internal buckets so a namespace literally
// named "_meta" cannot collide with the counters bucket.
var (
	metaBucket = []byte("_meta")
	ttlBucket  = []byte("_ttl")
	nsPrefix   = []byte("ns:")

	keyUsedBytes = []byte("usedBytes")
	keyKeyCount  = []byte("keyCount")
)

// record is the gob-encoded value stored under each user key. Opaque keys are
// the bbolt key itself; this is purely the value payload + metadata.
type record struct {
	Value       []byte
	ContentType string
	ExpiresAt   time.Time // zero == no expiry
	UpdatedAt   time.Time
}

// Store is a process-wide manager of per-tenant bbolt handles. The zero value is
// not usable; construct with Open.
type Store struct {
	dir string

	// minFreeBytes is a host-level free-disk floor (red-team RT5 #4). The
	// per-tenant 10MiB/10k caps bound a SINGLE tenant, but nothing bounds the
	// AGGREGATE: with one <tenant>.bolt per provisioned key and bbolt files that
	// never return freed pages to the OS, total physical KV disk grows unbounded
	// with key count. DiskFull() (statfs, unprivileged) lets the API refuse new
	// writes with 507 before the shared 35G disk is exhausted and the co-located
	// control plane / ~50 services are starved. 0 disables the gate.
	minFreeBytes int64

	mu     sync.Mutex // guards dbs map writes (open path) and closed
	dbs    sync.Map   // tenant(string) -> *bolt.DB
	closed bool
}

// Open initialises the store rooted at dir, creating it 0700 (deploy-only, the
// same posture as the rest of /var/lib/isobox). It does not open any tenant file
// yet; handles are opened lazily on first use. minFreeBytes is the host free-disk
// floor enforced by DiskFull (0 disables it).
func Open(dir string, minFreeBytes int64) (*Store, error) {
	if dir == "" {
		return nil, errors.New("memory: dir required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("memory: create dir: %w", err)
	}
	return &Store{dir: dir, minFreeBytes: minFreeBytes}, nil
}

// DiskFull reports whether free space on the KV directory's filesystem has
// dropped to/below the configured floor. The API consults this BEFORE a Put and
// answers 507 if true, so KV writes can never be the thing that exhausts the
// shared disk. statfs is unprivileged (works as user deploy). Fails OPEN (returns
// false) if statfs errors or the gate is disabled — a transient stat failure
// must not block all writes; the periodic check and the per-tenant caps remain.
func (s *Store) DiskFull() bool {
	if s.minFreeBytes <= 0 {
		return false
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.dir, &st); err != nil {
		return false
	}
	free := int64(st.Bavail) * int64(st.Bsize) // blocks available to unprivileged users
	return free < s.minFreeBytes
}

// validTenant enforces that tenant is either the literal open-mode sentinel
// "public" OR exactly a 64-char lowercase hex sha256. This is what keeps the
// join below contained: no separators, no traversal, no surprise filenames.
// Even though the caller derives tenant server-side, we never trust it blindly
// — defence in depth.
//
// IMPORTANT (red-team fix): we accept the literal "public" — the SAME sentinel
// auth.PublicTenant and volume.tenantRe accept — so KV and volumes share exactly
// ONE tenant namespace per caller (no validTenant/tenantRe split-brain the
// wiring can get wrong). We deliberately do NOT map "public" to
// hex(sha256("public")): that would collide with a real API key whose literal
// value is "public", defeating keystore's non-collision guarantee. "public" is
// not 64-hex so it can never collide with a key-derived tenant id, and it is
// path-safe (lowercase letters only) so it is a safe <tenant>.bolt filename.
func validTenant(tenant string) bool {
	if tenant == "public" {
		return true
	}
	if len(tenant) != 64 {
		return false
	}
	for i := 0; i < len(tenant); i++ {
		c := tenant[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// validNamespace bounds the namespace and restricts it to a safe charset, since
// it becomes part of a bucket name ("ns:"+ns).
func validNamespace(ns string) bool {
	if ns == "" || len(ns) > MaxNamespaceLen {
		return false
	}
	for i := 0; i < len(ns); i++ {
		c := ns[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == ':'
		if !ok {
			return false
		}
	}
	return true
}

// path returns the validated, contained bolt path for a tenant.
func (s *Store) path(tenant string) (string, error) {
	if !validTenant(tenant) {
		return "", ErrKVTenant
	}
	p := filepath.Join(s.dir, tenant+".bolt")
	// Belt-and-braces: the joined path must still live directly under dir.
	if filepath.Dir(p) != filepath.Clean(s.dir) {
		return "", ErrKVTenant
	}
	return p, nil
}

// getDB returns the single *bolt.DB for a tenant, opening it on first use. bbolt
// holds an exclusive flock per file, so exactly one handle per file is correct;
// the sync.Map + mutex double-check guarantees that in-process. Timeout means a
// stuck flock fails fast instead of hanging a request.
func (s *Store) getDB(tenant string) (*bolt.DB, error) {
	path, err := s.path(tenant)
	if err != nil {
		return nil, err
	}
	if v, ok := s.dbs.Load(tenant); ok {
		return v.(*bolt.DB), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrKVClosed
	}
	if v, ok := s.dbs.Load(tenant); ok { // double-check under lock
		return v.(*bolt.DB), nil
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("memory: open %s: %w", filepath.Base(path), err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, e := tx.CreateBucketIfNotExists(metaBucket); e != nil {
			return e
		}
		_, e := tx.CreateBucketIfNotExists(ttlBucket)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("memory: init %s: %w", filepath.Base(path), err)
	}
	s.dbs.Store(tenant, db)
	return db, nil
}

// Close closes all open tenant handles. Safe to call once at shutdown.
func (s *Store) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	var firstErr error
	s.dbs.Range(func(k, v any) bool {
		if err := v.(*bolt.DB).Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.dbs.Delete(k)
		return true
	})
	return firstErr
}

// --- accounting helpers ----------------------------------------------------

// sizeOf is the ONE definition of a record's footprint, used identically on
// add, overwrite-delta, delete, and sweep. Using the encoded length keeps the
// counter honest against the actual stored payload.
func sizeOf(key string, encoded []byte) int64 {
	return int64(len(key)) + int64(len(encoded))
}

func readKVMeta(tx *bolt.Tx) (used, count int64) {
	mb := tx.Bucket(metaBucket)
	if mb == nil {
		return 0, 0
	}
	if v := mb.Get(keyUsedBytes); len(v) == 8 {
		used = int64(binary.BigEndian.Uint64(v))
	}
	if v := mb.Get(keyKeyCount); len(v) == 8 {
		count = int64(binary.BigEndian.Uint64(v))
	}
	return used, count
}

func writeKVMeta(tx *bolt.Tx, used, count int64) error {
	mb, err := tx.CreateBucketIfNotExists(metaBucket)
	if err != nil {
		return err
	}
	if used < 0 {
		used = 0
	}
	if count < 0 {
		count = 0
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(used))
	if err := mb.Put(keyUsedBytes, append([]byte(nil), b[:]...)); err != nil {
		return err
	}
	binary.BigEndian.PutUint64(b[:], uint64(count))
	return mb.Put(keyKeyCount, append([]byte(nil), b[:]...))
}

// ttlKey encodes a TTL index entry as ts(8 BE) || nsLen(2 BE) || ns || userKey.
// Sorting by this key sorts by expiry timestamp first (so a forward cursor walks
// soonest-expiring first); embedding the full ns+key makes every entry unique
// for opaque keys (no separator byte is safe when keys are arbitrary bytes) and
// lets the sweep recover exactly which record to re-check.
func ttlKey(expires time.Time, ns, key string) []byte {
	out := make([]byte, 8+2+len(ns)+len(key))
	binary.BigEndian.PutUint64(out[0:8], uint64(expires.UnixNano()))
	binary.BigEndian.PutUint16(out[8:10], uint16(len(ns)))
	copy(out[10:], ns)
	copy(out[10+len(ns):], key)
	return out
}

// parseTTLKey extracts ns, key, and expiry-nanos from a _ttl index key.
func parseTTLKey(k []byte) (ns, key string, ts int64, ok bool) {
	if len(k) < 10 {
		return "", "", 0, false
	}
	ts = int64(binary.BigEndian.Uint64(k[0:8]))
	nsLen := int(binary.BigEndian.Uint16(k[8:10]))
	if 10+nsLen > len(k) {
		return "", "", 0, false
	}
	ns = string(k[10 : 10+nsLen])
	key = string(k[10+nsLen:])
	return ns, key, ts, true
}

func nsBucketName(ns string) []byte { return append(append([]byte(nil), nsPrefix...), ns...) }

func encodeRecord(r record) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeRecord(b []byte) (record, error) {
	var r record
	err := gob.NewDecoder(bytes.NewReader(b)).Decode(&r)
	return r, err
}

// --- public API ------------------------------------------------------------

// Put writes val under (tenant, ns, key), with an optional content type and TTL.
// The 10MiB/10k-key quota is enforced against POST-write totals INSIDE the same
// write transaction (it reads the old record, computes the byte delta, and
// aborts with ErrKVQuota before writing if the result would exceed a cap). An
// overwrite never changes keyCount; a new key increments it. ttl<=0 means no
// expiry.
func (s *Store) Put(tenant, ns, key string, val []byte, contentType string, ttl time.Duration) error {
	if !validNamespace(ns) {
		return ErrKVNamespace
	}
	if key == "" || len(key) > MaxKeyLen {
		return ErrKVKey
	}
	if len(val) > MaxValueLen {
		return ErrKVValueSize
	}
	db, err := s.getDB(tenant)
	if err != nil {
		return err
	}

	now := time.Now()
	rec := record{
		Value:       append([]byte(nil), val...),
		ContentType: contentType,
		UpdatedAt:   now,
	}
	if ttl > 0 {
		rec.ExpiresAt = now.Add(ttl)
	}
	encoded, err := encodeRecord(rec)
	if err != nil {
		return fmt.Errorf("memory: encode: %w", err)
	}
	if len(encoded) > MaxValueLen {
		return ErrKVValueSize
	}

	return db.Update(func(tx *bolt.Tx) error {
		nb, err := tx.CreateBucketIfNotExists(nsBucketName(ns))
		if err != nil {
			return err
		}
		used, count := readKVMeta(tx)

		newSize := sizeOf(key, encoded)
		var oldSize int64
		isNew := true
		// Read-modify-write: pull the prior record (if any) so we can compute a
		// signed delta and drop its stale _ttl entry — all in this same txn.
		if prev := nb.Get([]byte(key)); prev != nil {
			isNew = false
			oldSize = sizeOf(key, prev)
			if old, derr := decodeRecord(prev); derr == nil && !old.ExpiresAt.IsZero() {
				_ = tx.Bucket(ttlBucket).Delete(ttlKey(old.ExpiresAt, ns, key))
			}
		}

		newUsed := used - oldSize + newSize
		newCount := count
		if isNew {
			newCount = count + 1
		}
		if newUsed > MaxBytesPerTenant || newCount > MaxKeysPerTenant {
			return ErrKVQuota // abort BEFORE writing; txn rolls back cleanly
		}

		if err := nb.Put([]byte(key), encoded); err != nil {
			return err
		}
		if !rec.ExpiresAt.IsZero() {
			if err := tx.Bucket(ttlBucket).Put(ttlKey(rec.ExpiresAt, ns, key), []byte{}); err != nil {
				return err
			}
		}
		return writeKVMeta(tx, newUsed, newCount)
	})
}

// Get returns the stored value plus its content type, expiry, and a strong ETag
// (hex sha256 of the value bytes). An expired-but-not-yet-swept record is
// treated as absent (ErrKVNotFound) without deleting it — Get stays a read-only
// transaction; SweepExpired does the physical reclaim.
func (s *Store) Get(tenant, ns, key string) (val []byte, contentType string, expiresAt time.Time, etag string, err error) {
	if !validNamespace(ns) {
		return nil, "", time.Time{}, "", ErrKVNamespace
	}
	if key == "" || len(key) > MaxKeyLen {
		return nil, "", time.Time{}, "", ErrKVKey
	}
	db, err := s.getDB(tenant)
	if err != nil {
		return nil, "", time.Time{}, "", err
	}
	var rec record
	verr := db.View(func(tx *bolt.Tx) error {
		nb := tx.Bucket(nsBucketName(ns))
		if nb == nil {
			return ErrKVNotFound
		}
		raw := nb.Get([]byte(key))
		if raw == nil {
			return ErrKVNotFound
		}
		r, derr := decodeRecord(raw)
		if derr != nil {
			return ErrKVNotFound
		}
		if !r.ExpiresAt.IsZero() && !r.ExpiresAt.After(time.Now()) {
			return ErrKVNotFound // lazily hidden; reclaimed by SweepExpired
		}
		rec = r
		return nil
	})
	if verr != nil {
		return nil, "", time.Time{}, "", verr
	}
	sum := sha256.Sum256(rec.Value)
	etag = `"` + hex.EncodeToString(sum[:]) + `"`
	return rec.Value, rec.ContentType, rec.ExpiresAt, etag, nil
}

// Delete removes (tenant, ns, key) and reconciles the _ttl index and _meta
// counters in the same transaction. Deleting a missing key is a no-op (nil).
func (s *Store) Delete(tenant, ns, key string) error {
	if !validNamespace(ns) {
		return ErrKVNamespace
	}
	if key == "" || len(key) > MaxKeyLen {
		return ErrKVKey
	}
	db, err := s.getDB(tenant)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		nb := tx.Bucket(nsBucketName(ns))
		if nb == nil {
			return nil
		}
		prev := nb.Get([]byte(key))
		if prev == nil {
			return nil
		}
		used, count := readKVMeta(tx)
		freed := sizeOf(key, prev)
		if old, derr := decodeRecord(prev); derr == nil && !old.ExpiresAt.IsZero() {
			_ = tx.Bucket(ttlBucket).Delete(ttlKey(old.ExpiresAt, ns, key))
		}
		if err := nb.Delete([]byte(key)); err != nil {
			return err
		}
		return writeKVMeta(tx, used-freed, count-1)
	})
}

// List returns up to limit keys in ns whose key has the given prefix, in bbolt's
// byte order, starting after cursor (an opaque base64url token returned as
// nextCursor). Expired records are skipped. nextCursor is non-empty only when
// more keys may remain; pass it back verbatim to page. limit<=0 or >1000 is
// clamped to a sane default.
func (s *Store) List(tenant, ns, prefix string, limit int, cursor string) (keys []string, nextCursor string, err error) {
	if !validNamespace(ns) {
		return nil, "", ErrKVNamespace
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	start, derr := decodeCursor(cursor)
	if derr != nil {
		return nil, "", fmt.Errorf("memory: bad cursor: %w", derr)
	}
	db, err := s.getDB(tenant)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	pfx := []byte(prefix)

	verr := db.View(func(tx *bolt.Tx) error {
		nb := tx.Bucket(nsBucketName(ns))
		if nb == nil {
			return nil // no such namespace yet -> empty page
		}
		c := nb.Cursor()
		var k, v []byte
		if start != nil {
			// Seek to the cursor key, then advance past it (cursor is exclusive).
			k, v = c.Seek(start)
			if k != nil && bytes.Equal(k, start) {
				k, v = c.Next()
			}
		} else if len(pfx) > 0 {
			k, v = c.Seek(pfx)
		} else {
			k, v = c.First()
		}
		for ; k != nil; k, v = c.Next() {
			if len(pfx) > 0 && !bytes.HasPrefix(k, pfx) {
				break // keys are sorted; past the prefix range
			}
			if r, e := decodeRecord(v); e == nil {
				if !r.ExpiresAt.IsZero() && !r.ExpiresAt.After(now) {
					continue // skip expired
				}
			}
			if len(keys) == limit {
				// There is at least one more matching key -> emit a cursor
				// pointing at the LAST returned key (exclusive on next call).
				nextCursor = encodeCursor([]byte(keys[len(keys)-1]))
				return nil
			}
			keys = append(keys, string(append([]byte(nil), k...)))
		}
		return nil
	})
	if verr != nil {
		return nil, "", verr
	}
	return keys, nextCursor, nil
}

// Stats reports a tenant's current usage as tracked by the in-txn counters.
// expiredPending is best-effort (counts _ttl entries already past now) and is
// informational only.
func (s *Store) Stats(tenant string) (usedBytes, keyCount, expiredPending int64, err error) {
	if !validTenant(tenant) {
		return 0, 0, 0, ErrKVTenant
	}
	// If the tenant has never been touched, there is no file and no usage.
	if _, ok := s.dbs.Load(tenant); !ok {
		if p, perr := s.path(tenant); perr == nil {
			if _, statErr := os.Stat(p); os.IsNotExist(statErr) {
				return 0, 0, 0, nil
			}
		}
	}
	db, err := s.getDB(tenant)
	if err != nil {
		return 0, 0, 0, err
	}
	now := time.Now().UnixNano()
	verr := db.View(func(tx *bolt.Tx) error {
		usedBytes, keyCount = readKVMeta(tx)
		if tb := tx.Bucket(ttlBucket); tb != nil {
			c := tb.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				if _, _, ts, ok := parseTTLKey(k); ok && ts <= now {
					expiredPending++
				} else {
					break // sorted by ts; first non-expired ends the run
				}
			}
		}
		return nil
	})
	if verr != nil {
		return 0, 0, 0, verr
	}
	return usedBytes, keyCount, expiredPending, nil
}

// SweepExpired physically reclaims expired records across all currently-open
// tenant handles. It walks each _ttl index in ascending-timestamp order; for
// every entry whose timestamp is <= now it RE-READS the actual record and
// confirms it is genuinely expired before deleting record + _ttl entry and
// decrementing _meta (this tolerates any index/record drift). It stops scanning
// a tenant at the first not-yet-expired entry. Returns the number of records
// reclaimed. Tenants whose handle is not open are skipped — their expired data
// stays hidden by Get/List and is reclaimed the next time the file is opened and
// swept.
func (s *Store) SweepExpired() (reclaimed int, err error) {
	var dbs []*bolt.DB
	s.dbs.Range(func(_, v any) bool {
		dbs = append(dbs, v.(*bolt.DB))
		return true
	})
	for _, db := range dbs {
		n, e := sweepDB(db)
		reclaimed += n
		if e != nil && err == nil {
			err = e
		}
	}
	return reclaimed, err
}

func sweepDB(db *bolt.DB) (int, error) {
	now := time.Now()
	nowNanos := now.UnixNano()
	reclaimed := 0
	// Collect due entries in a read txn, then delete in a write txn, so we never
	// mutate a cursor mid-iteration. The _ttl bucket is small (only keys with a
	// TTL appear), so this is cheap.
	type due struct {
		ns, key string
		ttlK    []byte
	}
	var batch []due
	if err := db.View(func(tx *bolt.Tx) error {
		tb := tx.Bucket(ttlBucket)
		if tb == nil {
			return nil
		}
		c := tb.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			ns, key, ts, ok := parseTTLKey(k)
			if !ok {
				batch = append(batch, due{ttlK: append([]byte(nil), k...)}) // junk index entry; drop it
				continue
			}
			if ts > nowNanos {
				break // ascending by ts -> nothing further is due
			}
			batch = append(batch, due{ns: ns, key: key, ttlK: append([]byte(nil), k...)})
		}
		return nil
	}); err != nil {
		return 0, err
	}
	if len(batch) == 0 {
		return 0, nil
	}
	err := db.Update(func(tx *bolt.Tx) error {
		used, count := readKVMeta(tx)
		tb, e := tx.CreateBucketIfNotExists(ttlBucket)
		if e != nil {
			return e
		}
		for _, d := range batch {
			if d.ns == "" && d.key == "" { // pure junk index entry
				_ = tb.Delete(d.ttlK)
				continue
			}
			nb := tx.Bucket(nsBucketName(d.ns))
			if nb == nil {
				_ = tb.Delete(d.ttlK)
				continue
			}
			raw := nb.Get([]byte(d.key))
			if raw == nil {
				_ = tb.Delete(d.ttlK) // record already gone; just clean the index
				continue
			}
			r, derr := decodeRecord(raw)
			// Re-confirm expiry against the actual record; if the record was
			// rewritten with a later/zero expiry, its _ttl key differs, so this
			// stale index entry no longer matches and is safe to drop without
			// touching the live record.
			if derr == nil && (r.ExpiresAt.IsZero() || r.ExpiresAt.After(now)) {
				_ = tb.Delete(d.ttlK)
				continue
			}
			used -= sizeOf(d.key, raw)
			count--
			if e := nb.Delete([]byte(d.key)); e != nil {
				return e
			}
			_ = tb.Delete(d.ttlK)
			reclaimed++
		}
		return writeKVMeta(tx, used, count)
	})
	if err != nil {
		return 0, err
	}
	return reclaimed, nil
}

// --- opaque cursor codec ---------------------------------------------------
//
// Keys are arbitrary bytes, so the pagination cursor is the last-returned key
// base64url-encoded (URL/header safe) and treated as opaque by callers.

func encodeCursor(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decodeCursor(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
