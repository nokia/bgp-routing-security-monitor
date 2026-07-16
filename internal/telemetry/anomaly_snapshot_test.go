package telemetry

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// windowStat is a comparable summary of a window's state used to assert that a
// restored window matches the pre-save one. Because median/MAD are recomputed
// (never persisted), comparing them here confirms the raw values round-tripped.
type windowStat struct {
	median float64
	mad    float64
	ok     bool
	count  int
	pos    int
	filled bool
}

func statOf(w *metricWindow) windowStat {
	med, mad, ok := w.medianMAD()
	return windowStat{med, mad, ok, w.count(), w.pos, w.filled}
}

// snapStats summarizes every window in a detector, keyed by "cache/metric".
func snapStats(d *Detector) map[string]windowStat {
	out := map[string]windowStat{}
	d.mu.Lock()
	defer d.mu.Unlock()
	for cache, metrics := range d.windows {
		for metric, w := range metrics {
			out[cache+"/"+metric] = statOf(w)
		}
	}
	return out
}

func TestSnapshotRoundTrip(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	base := time.Unix(1_700_000_000, 0)

	// cacheA: two metrics, one window driven well past cap to force wraparound.
	for i := 0; i < 620; i++ {
		d.ObserveSync("cacheA", base.Add(time.Duration(i)*time.Second), map[string]float64{
			MetricVRPAnnounced: float64(10 + i%13),
			MetricSyncDuration: float64(1_000_000 * (5 + i%7)),
		})
	}
	// cacheB: partially filled window (below cap) to exercise pos/!filled.
	for i := 0; i < 40; i++ {
		d.ObserveSync("cacheB", base.Add(time.Duration(i)*time.Second), map[string]float64{
			MetricASPAWithdrawn: float64(i % 4),
		})
	}

	pre := snapStats(d)
	if len(pre) != 3 {
		t.Fatalf("expected 3 windows populated, got %d", len(pre))
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := d.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Confirm median/MAD are NOT persisted: the raw fields are present, the
	// derived ones are absent from the serialized document.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, want := range []string{`"schema_version": 1`, `"pos"`, `"filled"`, `"values"`} {
		if !strings.Contains(doc, want) {
			t.Fatalf("snapshot missing expected field %s\n%s", want, doc)
		}
	}
	for _, banned := range []string{"median", "mad"} {
		if strings.Contains(doc, banned) {
			t.Fatalf("snapshot unexpectedly persisted derived stat %q", banned)
		}
	}

	// Load into a fresh detector and confirm every window matches, with
	// median/MAD recomputed from restored raw values.
	d2 := NewDetector(DefaultAnomalyConfig())
	if err := d2.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := snapStats(d2)
	if !reflect.DeepEqual(got, pre) {
		t.Fatalf("restored windows differ from pre-save:\npre = %+v\ngot = %+v", pre, got)
	}
}

func TestLoadNonexistentReturnsIsNotExist(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	err := d.Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("Load on missing file returned nil")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("error does not satisfy os.IsNotExist: %v", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error does not satisfy errors.Is(fs.ErrNotExist): %v", err)
	}
}

func TestLoadSchemaMismatchLeavesDetectorUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	bad := `{"schema_version":999,"saved_at":"2026-07-16T15:00:00Z",` +
		`"caches":{"cacheA":{"vrp_announced":{"pos":0,"filled":false,"values":[1,2,3]}}}}`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}

	d := NewDetector(DefaultAnomalyConfig())
	err := d.Load(path)
	if err == nil {
		t.Fatal("Load on schema mismatch returned nil")
	}
	if !errors.Is(err, ErrAnomalySnapshotSchemaMismatch) {
		t.Fatalf("error is not ErrAnomalySnapshotSchemaMismatch: %v", err)
	}
	if got := len(snapStats(d)); got != 0 {
		t.Fatalf("detector windows modified on schema mismatch: %d windows", got)
	}
}

func TestSaveAtomicRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	d := NewDetector(DefaultAnomalyConfig())
	d.ObserveSync("cacheA", time.Unix(1_700_000_000, 0), map[string]float64{MetricVRPAnnounced: 7})
	if err := d.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The temp file must not linger after a successful save.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf(".tmp file lingered after successful Save (stat err = %v)", err)
	}
	// File is written with 0o600 per spec.
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("snapshot file perm = %o, want 600", perm)
	}

	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Inject a write failure: occupy the ".tmp" path with a directory so the
	// temp-file write cannot succeed.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	// Mutate the detector so a (hypothetically) successful save would produce
	// different bytes than the good target.
	d.ObserveSync("cacheA", time.Unix(1_700_000_100, 0), map[string]float64{MetricVRPAnnounced: 999})
	if err := d.Save(path); err == nil {
		t.Fatal("Save succeeded despite an unwritable .tmp path")
	}

	// The target must be byte-for-byte unchanged: no truncation, no corruption.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(good, after) {
		t.Fatalf("target file changed after a failed Save:\nbefore = %s\nafter  = %s", good, after)
	}
}

func TestRestoreCapMismatchIsNoOp(t *testing.T) {
	w := newMetricWindow(3)
	w.add(1)
	w.add(2)
	before := w.snapshot()

	// Too many values (cap changed from 3 to 5): must be a no-op, not a panic.
	w.restore(windowSnapshot{Pos: 0, Filled: true, Values: []float64{10, 20, 30, 40, 50}})
	if after := w.snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatalf("restore with oversized snapshot mutated window: before=%+v after=%+v", before, after)
	}

	// Empty/nil values: also a no-op, not a panic.
	w.restore(windowSnapshot{})
	if after := w.snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatalf("restore with empty snapshot mutated window: before=%+v after=%+v", before, after)
	}

	// Matching cap: restore applies.
	w.restore(windowSnapshot{Pos: 1, Filled: true, Values: []float64{7, 8, 9}})
	got := w.snapshot()
	want := windowSnapshot{Pos: 1, Filled: true, Values: []float64{7, 8, 9}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("matching-cap restore = %+v, want %+v", got, want)
	}
}

func TestEnsureAnomalySnapshotDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "sub", "baseline.json")
	if err := EnsureAnomalySnapshotDir(path); err != nil {
		t.Fatalf("EnsureAnomalySnapshotDir: %v", err)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected a directory")
	}
}
