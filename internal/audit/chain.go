// Package audit provides a tamper-evident record of security decisions.
//
// What this does and does not give you is worth being precise about, because
// "immutable audit log" is a phrase that gets used loosely.
//
// Each record commits to the one before it by hash, so changing or removing a
// record in the middle breaks every link after it. That makes edits *evident*.
// It does not make them *impossible*: somebody who can rewrite the entire store
// can also recompute the whole chain. Two things close that gap, and both are
// implemented here:
//
//   - The head hash is published as a checkpoint. Anchoring that checkpoint
//     somewhere the same operator cannot rewrite — a signed evidence bundle, a
//     transparency log, an auditor's inbox — is what turns "evident to someone
//     holding an older copy" into "evident, full stop".
//   - Truncating the tail is the attack a naive chain misses entirely, because
//     a shorter valid chain is still internally consistent. The checkpoint
//     records the length as well as the head, so a log that got shorter is
//     detectable.
//
// Without an externally anchored checkpoint this is tamper-evident against
// anyone who does not control the store, and no more. The documentation says
// so rather than implying otherwise.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// GenesisHash is the predecessor of the first record. A fixed, non-zero value
// so an empty chain and a chain whose first record claims no predecessor are
// distinguishable.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// EventType classifies what happened. These are the decisions an auditor cares
// about: who let what through, and on what basis.
type EventType string

const (
	// EventRiskAccepted records an ArtifactException: a human accepting a
	// finding that policy would otherwise block.
	EventRiskAccepted EventType = "RiskAccepted"
	// EventVerdictIssued records a scan reaching a verdict.
	EventVerdictIssued EventType = "VerdictIssued"
	// EventDeploymentBlocked records the admission gate refusing a workload.
	EventDeploymentBlocked EventType = "DeploymentBlocked"
	// EventDeploymentAdmitted records the gate allowing one through.
	EventDeploymentAdmitted EventType = "DeploymentAdmitted"
	// EventExceptionExpired records a waiver lapsing.
	EventExceptionExpired EventType = "ExceptionExpired"
	// EventExceptionRevoked records a waiver withdrawn before expiry.
	EventExceptionRevoked EventType = "ExceptionRevoked"
	// EventPolicyChanged records a change to the rules themselves, which
	// silently reinterprets every verdict that follows.
	EventPolicyChanged EventType = "PolicyChanged"
)

// Record is one entry in the chain.
//
// Field names are part of the hash preimage, so renaming one invalidates every
// existing chain. They are deliberately terse and final.
type Record struct {
	// Seq is the position in the chain, starting at 1.
	Seq uint64 `json:"seq"`
	// Time is when the event was recorded, in UTC, to second precision.
	//
	// Truncated deliberately: sub-second precision varies with serialization
	// and would make a chain fail to re-verify after a round trip through
	// storage that rounds it.
	Time time.Time `json:"time"`
	// Type of event.
	Type EventType `json:"type"`
	// Subject is what the event is about, as "model/version".
	Subject string `json:"subject"`
	// Actor is the authenticated identity responsible. "system" for decisions
	// the operator made without a human.
	Actor string `json:"actor"`
	// Detail carries event-specific fields. Keys are sorted when hashed, so
	// map iteration order cannot change the hash.
	Detail map[string]string `json:"detail,omitempty"`
	// PrevHash links to the preceding record.
	PrevHash string `json:"prevHash"`
	// Hash commits to every field above.
	Hash string `json:"hash"`
}

// Canonical renders the hash preimage for a record.
//
// Hand-built rather than delegated to a JSON encoder. An encoder's output can
// change with a library upgrade — field ordering, escaping, number formatting —
// and a hash that silently changes meaning between versions would invalidate
// every stored chain. This format is explicit and frozen.
func (r Record) Canonical() []byte {
	var b strings.Builder
	b.WriteString("seq=")
	b.WriteString(strconv.FormatUint(r.Seq, 10))
	b.WriteString("\ntime=")
	b.WriteString(r.Time.UTC().Format(time.RFC3339))
	b.WriteString("\ntype=")
	b.WriteString(string(r.Type))
	b.WriteString("\nsubject=")
	b.WriteString(escape(r.Subject))
	b.WriteString("\nactor=")
	b.WriteString(escape(r.Actor))
	b.WriteString("\nprev=")
	b.WriteString(r.PrevHash)
	b.WriteString("\ndetail=")

	keys := make([]string, 0, len(r.Detail))
	for k := range r.Detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(escape(k))
		b.WriteString(":")
		b.WriteString(escape(r.Detail[k]))
		b.WriteString(";")
	}
	b.WriteString("\n")
	return []byte(b.String())
}

// escape neutralises the delimiters used by the canonical form.
//
// Without this, a detail value containing ";" or ":" could be crafted so two
// different records produce identical preimages — letting one acceptance be
// swapped for another without breaking the chain.
func escape(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		"\n", `\n`,
		":", `\c`,
		";", `\s`,
		"=", `\e`,
	)
	return replacer.Replace(s)
}

// ComputeHash returns the hash a record should carry.
func (r Record) ComputeHash() string {
	sum := sha256.Sum256(r.Canonical())
	return hex.EncodeToString(sum[:])
}

// Seal fills in the linkage and hash for a record being appended after prev.
func Seal(r Record, prev *Record) Record {
	if prev == nil {
		r.Seq = 1
		r.PrevHash = GenesisHash
	} else {
		r.Seq = prev.Seq + 1
		r.PrevHash = prev.Hash
	}
	r.Time = r.Time.UTC().Truncate(time.Second)
	r.Hash = r.ComputeHash()
	return r
}

// Checkpoint commits to the state of a chain at a moment.
//
// Publishing this is what makes tail truncation detectable: a log that has been
// shortened still verifies internally, but cannot match a checkpoint that
// remembers a greater length.
type Checkpoint struct {
	// Length is how many records the chain held.
	Length uint64 `json:"length"`
	// Head is the hash of the final record.
	Head string `json:"head"`
	// Time the checkpoint was taken.
	Time time.Time `json:"time"`
}

// Verification is the outcome of checking a chain.
type Verification struct {
	// Valid is true only when every record links and hashes correctly and any
	// supplied checkpoint is satisfied.
	Valid bool `json:"valid"`
	// Length of the chain examined.
	Length uint64 `json:"length"`
	// Head hash of the chain examined.
	Head string `json:"head"`
	// Problems describes what failed, in chain order.
	Problems []string `json:"problems,omitempty"`
}

// Verify walks a chain and reports whether it is intact.
//
// records must be in sequence order. A checkpoint is optional; supplying one
// upgrades the check from "internally consistent" to "consistent with what was
// previously published", which is the only way to catch a truncated tail or a
// wholesale rewrite.
func Verify(records []Record, checkpoint *Checkpoint) Verification {
	v := Verification{Valid: true, Head: GenesisHash}

	prevHash := GenesisHash
	for i, r := range records {
		wantSeq := uint64(i + 1)
		if r.Seq != wantSeq {
			v.Problems = append(v.Problems, fmt.Sprintf(
				"record %d claims sequence %d: a record was inserted, removed, or reordered",
				i+1, r.Seq))
			v.Valid = false
		}
		if r.PrevHash != prevHash {
			v.Problems = append(v.Problems, fmt.Sprintf(
				"record %d does not follow record %d: expected predecessor %s, found %s",
				r.Seq, r.Seq-1, short(prevHash), short(r.PrevHash)))
			v.Valid = false
		}
		if got := r.ComputeHash(); got != r.Hash {
			v.Problems = append(v.Problems, fmt.Sprintf(
				"record %d has been modified since it was written: contents hash to %s but it carries %s",
				r.Seq, short(got), short(r.Hash)))
			v.Valid = false
		}
		prevHash = r.Hash
	}

	v.Length = uint64(len(records))
	v.Head = prevHash

	if checkpoint != nil {
		switch {
		case v.Length < checkpoint.Length:
			v.Problems = append(v.Problems, fmt.Sprintf(
				"the log is shorter than its checkpoint: %d records now, %d at checkpoint time. "+
					"Records have been deleted from the end, which an unanchored chain cannot show.",
				v.Length, checkpoint.Length))
			v.Valid = false
		case v.Length == checkpoint.Length && v.Head != checkpoint.Head:
			v.Problems = append(v.Problems, fmt.Sprintf(
				"the log has the checkpointed length but a different head (%s, checkpoint says %s): "+
					"it has been rewritten.", short(v.Head), short(checkpoint.Head)))
			v.Valid = false
		}
	}
	return v
}

// Head returns the checkpoint for a verified chain.
func Head(records []Record) Checkpoint {
	cp := Checkpoint{Length: uint64(len(records)), Head: GenesisHash, Time: time.Now().UTC().Truncate(time.Second)}
	if len(records) > 0 {
		cp.Head = records[len(records)-1].Hash
	}
	return cp
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
