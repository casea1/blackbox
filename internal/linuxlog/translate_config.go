// The audit system itself: rule and setting changes (CONFIG_CHANGE),
// including refused ones, and auditd stopping.

package linuxlog

import (
	"fmt"
	"regexp"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// refused reports whether the kernel turned a change down: it writes res=0
// (newer kernels: res=failed) when the rules are locked with -e 2.
func refused(r *Record) bool {
	res := r.Get("res")
	return res == "0" || res == "failed" || res == "no"
}

func (t *Translator) configChange(r *Record) *event.Event {
	actor := t.actor(r)
	if refused(r) {
		return t.refusedChange(r, actor)
	}
	if v, ok := r.Fields["audit_enabled"]; ok && r.Get("op") != "add_rule" && r.Get("op") != "remove_rule" {
		switch v {
		case "0":
			return &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "audit_disabled", User: actor,
				Summary: fmt.Sprintf("Kernel auditing was turned OFF by %s — nothing is recorded until it is turned back on.", orUnknown(actor))}
		case "2":
			if actor == "" {
				return nil // rules locked at boot, as the STIG requires
			}
			return &event.Event{Category: event.CatIntegrity, Severity: event.SevInfo, Action: "audit_locked", User: actor,
				Summary: fmt.Sprintf("%s locked the audit rules (they cannot be changed until reboot).", actor)}
		case "1":
			if actor == "" || r.Fields["old"] == "1" {
				return nil
			}
			return &event.Event{Category: event.CatIntegrity, Severity: event.SevLow, Action: "audit_enabled", User: actor,
				Summary: fmt.Sprintf("%s turned kernel auditing on.", actor)}
		}
	}
	if actor == "" {
		return nil // rules loaded at boot
	}
	op := r.Get("op")
	key := r.Get("key")
	rule := ""
	if key != "" {
		rule = " (" + key + ")"
	}
	e := &event.Event{Category: event.CatIntegrity, User: actor, Target: key}
	switch op {
	case "remove_rule":
		e.Action, e.Severity = "audit_rule_removed", event.SevHigh
		e.Summary = fmt.Sprintf("%s removed an audit rule%s — activity it covered is no longer recorded.", actor, rule)
		e.DedupeKey = "auditrule|remove"
	case "add_rule":
		e.Action, e.Severity = "audit_rule_added", event.SevMedium
		e.Summary = fmt.Sprintf("%s added an audit rule%s.", actor, rule)
		e.DedupeKey = "auditrule|add"
	default:
		e.Action, e.Severity = "audit_config_changed", event.SevMedium
		e.Summary = fmt.Sprintf("%s changed the audit configuration (%s).", actor, orUnknownOp(op))
	}
	return e
}

// refusedChange is an attempt to change auditing that the kernel refused,
// normally because the rules are locked until reboot (-e 2). Nothing
// changed, but someone tried: auditing stayed on.
func (t *Translator) refusedChange(r *Record, actor string) *event.Event {
	who := actor
	if who == "" {
		who = "A system process (no logged-in user)"
	}
	why := "the change was refused"
	if r.Get("audit_enabled") == "2" || r.Get("old") == "2" {
		why = "refused because the audit rules are locked until the next reboot"
	}
	e := &event.Event{Category: event.CatIntegrity, Severity: event.SevMedium, Action: "audit_rules_refused", User: actor,
		Outcome: "failure", Target: r.Get("key")}
	switch op := r.Get("op"); {
	case op == "remove_rule":
		e.Summary = fmt.Sprintf("%s tried to remove audit rules; %s. Auditing stayed on.", who, why)
		e.DedupeKey = "auditrule|refused|remove"
	case op == "add_rule":
		e.Summary = fmt.Sprintf("%s tried to add an audit rule; %s.", who, why)
		e.DedupeKey = "auditrule|refused|add"
	case r.Get("audit_enabled") == "0":
		e.Severity = event.SevHigh
		e.Summary = fmt.Sprintf("%s tried to turn off auditing; %s. Auditing stayed on.", who, why)
		e.DedupeKey = "auditrule|refused|off"
	default:
		e.Summary = fmt.Sprintf("%s tried to change the audit configuration (%s); %s.", who, orUnknownOp(op), why)
		e.DedupeKey = "auditrule|refused|" + op
	}
	if actor == "" {
		// A service reloading the rules (an auditd update, augenrules at
		// a restart) is refused the same way; no person tried anything.
		e.Severity = event.SevLow
	}
	e.AddDetail("Operation", r.Get("op"))
	e.AddDetail("Result", "refused")
	return e
}

func orUnknownOp(op string) string {
	if op == "" {
		return "setting not recorded"
	}
	return op
}

// stopsAuditd matches a command that stops or restarts the audit service.
//
// StopsAuditd is exported for the report, which joins an auditd stop to the
// person's sudo command from the journal (U8b, sudo-rs).
func StopsAuditd(cmd string) bool { return stopsAuditd.MatchString(cmd) }

var stopsAuditd = regexp.MustCompile(`\b(systemctl\s+(\S+\s+)*(stop|kill|restart|try-restart|reload-or-restart)\s+(\S+\s+)*auditd(\.service)?\b|service\s+auditd\s+(stop|restart|condrestart|force-reload)\b|(pkill|killall)\s+(\S+\s+)*auditd\b)`)

// stoppedBy finds the person whose command stopped the audit service:
// systemd sends the signal, so auditd's own record names no one.
func (t *Translator) stoppedBy(tm time.Time, host string) (who, cmd string) {
	for i := len(t.recent) - 1; i >= 0; i-- {
		c := t.recent[i]
		if c.host != host || c.who == "" || tm.Sub(c.t) > 2*time.Minute || c.t.After(tm.Add(5*time.Second)) {
			continue
		}
		if stopsAuditd.MatchString(c.cmd) {
			return c.who, c.cmd
		}
	}
	return "", ""
}

func (t *Translator) auditdStopped(r *Record, prio int) *event.Event {
	actor := t.actor(r)
	cmd := ""
	if actor == "" {
		actor, cmd = t.stoppedBy(r.Time, t.hostOf(r))
	} else if r.Get("pid") == "1" {
		// systemd (pid 1) sent the signal, so the record says root even
		// when a person asked for it (U8): name them when known.
		if who, c := t.stoppedBy(r.Time, t.hostOf(r)); who != "" {
			actor, cmd = who, c
		}
	}
	e := &event.Event{Category: event.CatIntegrity, Action: "audit_stopped", User: actor,
		DedupeKey: "auditd-stop", Priority: prio, Command: cmd}
	if actor != "" {
		e.Severity = event.SevHigh
		e.Summary = fmt.Sprintf("The audit service (auditd) was stopped by %s — events are not recorded while it is stopped.", actor)
		if cmd != "" {
			e.Summary = fmt.Sprintf("The audit service (auditd) was stopped by %s (%s) — events are not recorded while it is stopped.", actor, cmd)
			e.AddDetail("Command", cmd)
		}
	} else {
		e.Severity = event.SevLow
		e.Summary = "The audit service (auditd) stopped (normal during a system shutdown)."
	}
	return e
}
