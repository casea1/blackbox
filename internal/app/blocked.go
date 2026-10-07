package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/store"
)

// A scheduled run refused because another run held the lock for longer
// than it waits is noted in blocked.json (LOCK1): status and the status
// icon say collection is blocked while that run still holds it, and the
// next collection records the gap with its run, so it reaches the next
// report (on the collector too). It is written without the lock, which
// another run holds; only refused runs write it.

func blockedPath(dataDir string) string { return filepath.Join(dataDir, "blocked.json") }

func readBlocked(dataDir string) *store.Blocked {
	b, err := os.ReadFile(blockedPath(dataDir))
	if err != nil {
		return nil
	}
	var bl store.Blocked
	if json.Unmarshal(b, &bl) != nil || bl.Refused == 0 {
		return nil
	}
	return &bl
}

// noteBlocked records a scheduled run refused because of the lock.
func (a *App) noteBlocked(err error) {
	var busy *store.BusyError
	if !errors.As(err, &busy) {
		return
	}
	now := a.now()
	bl := readBlocked(a.Cfg.DataDir)
	if bl == nil || bl.Holder.PID != busy.Holder.PID || !bl.Holder.Since.Equal(busy.Holder.Since) {
		if bl == nil {
			bl = &store.Blocked{First: now}
		}
		// Another run holds it now: the gap still starts at the first
		// refusal.
		bl.Holder = busy.Holder
	}
	bl.Last = now
	bl.Refused++
	b, _ := json.Marshal(bl)
	store.WriteFileAtomic(blockedPath(a.Cfg.DataDir), b, 0o640)
}

// liveOptions are the options for this computer's collection, with any
// gap left by refused runs.
func (a *App) liveOptions() collect.Options {
	return collect.Options{Version: a.Version, Now: a.now, Logf: a.Logf, Blocked: readBlocked(a.Cfg.DataDir)}
}

// collected clears what a collection has recorded.
func (a *App) collected(opt collect.Options) {
	if b := opt.Blocked; b != nil {
		a.logf("collection was blocked from %s to %s: %d scheduled run%s refused because a run held the lock (%s)",
			stampLocal(b.First, a.loc()), stampLocal(b.Until, a.loc()), b.Refused, map[bool]string{true: "s"}[b.Refused != 1], b.Holder)
		// A run refused while this one collected (a slow run) wrote a new
		// record naming this one: that stays.
		if now := readBlocked(a.Cfg.DataDir); now != nil && now.Holder == b.Holder && now.Refused == b.Refused {
			os.Remove(blockedPath(a.Cfg.DataDir))
		}
	}
}

// blockedNow is the block still in force: refused runs recorded, and the
// run they waited for still holding the lock.
func blockedNow(dataDir string, st *store.Store) *store.Blocked {
	bl := readBlocked(dataDir)
	if bl == nil {
		return nil
	}
	h, held := st.LockHolder()
	if !held || h.PID != bl.Holder.PID {
		return nil
	}
	return bl
}
