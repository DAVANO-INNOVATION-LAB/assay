package audit

import (
	"strings"
	"testing"
	"time"
)

func build(t *testing.T, n int) []Record {
	t.Helper()
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	var chain []Record
	var prev *Record
	for i := 0; i < n; i++ {
		r := Record{
			Time:    base.Add(time.Duration(i) * time.Minute),
			Type:    EventRiskAccepted,
			Subject: "fraud-detector/v3",
			Actor:   "alice@davano.net",
			Detail:  map[string]string{"finding": "CVE-2025-1234", "reason": "compensating control"},
		}
		sealed := Seal(r, prev)
		chain = append(chain, sealed)
		prev = &chain[len(chain)-1]
	}
	return chain
}

func TestIntactChainVerifies(t *testing.T) {
	chain := build(t, 5)
	v := Verify(chain, nil)
	if !v.Valid {
		t.Fatalf("an untouched chain must verify, problems: %v", v.Problems)
	}
	if v.Length != 5 {
		t.Fatalf("want length 5, got %d", v.Length)
	}
}

func TestEmptyChainVerifies(t *testing.T) {
	v := Verify(nil, nil)
	if !v.Valid || v.Head != GenesisHash {
		t.Fatalf("an empty chain is vacuously intact, got %+v", v)
	}
}

// Editing a record's content must break its own hash.
func TestModifiedRecordIsDetected(t *testing.T) {
	chain := build(t, 5)
	chain[2].Detail["reason"] = "actually it was fine"

	v := Verify(chain, nil)
	if v.Valid {
		t.Fatal("a modified record must not verify")
	}
	if !strings.Contains(strings.Join(v.Problems, " "), "modified") {
		t.Fatalf("the problem should name the modification, got %v", v.Problems)
	}
}

// Changing who approved something is the tampering that matters most.
func TestChangedActorIsDetected(t *testing.T) {
	chain := build(t, 3)
	chain[1].Actor = "someone-else@davano.net"

	if Verify(chain, nil).Valid {
		t.Fatal("rewriting the approver must break the chain")
	}
}

// Removing a record from the middle must break the link across the gap.
func TestDeletedRecordIsDetected(t *testing.T) {
	chain := build(t, 5)
	tampered := append(append([]Record{}, chain[:2]...), chain[3:]...)

	v := Verify(tampered, nil)
	if v.Valid {
		t.Fatal("deleting a record from the middle must not verify")
	}
}

func TestReorderedRecordsAreDetected(t *testing.T) {
	chain := build(t, 4)
	chain[1], chain[2] = chain[2], chain[1]

	if Verify(chain, nil).Valid {
		t.Fatal("reordering must not verify")
	}
}

// The tail-truncation case: a shortened chain is still internally consistent,
// so only a checkpoint catches it. This is the whole reason checkpoints exist.
func TestTruncationIsOnlyCaughtByCheckpoint(t *testing.T) {
	chain := build(t, 6)
	cp := Head(chain)

	truncated := chain[:3]

	if v := Verify(truncated, nil); !v.Valid {
		t.Fatal("a truncated chain is internally consistent — this test documents that " +
			"a bare chain cannot catch truncation, so the checkpoint below is load-bearing")
	}

	v := Verify(truncated, &cp)
	if v.Valid {
		t.Fatal("a checkpoint must catch a truncated log")
	}
	if !strings.Contains(strings.Join(v.Problems, " "), "shorter") {
		t.Fatalf("the problem should say the log got shorter, got %v", v.Problems)
	}
}

// A wholesale rewrite produces a valid chain of the same length with a
// different head. Only the checkpoint sees it.
func TestRewrittenChainIsCaughtByCheckpoint(t *testing.T) {
	original := build(t, 4)
	cp := Head(original)

	forged := build(t, 4)
	forged[3].Actor = "attacker@evil.example"
	// Re-seal so the forged chain is internally perfect.
	var prev *Record
	for i := range forged {
		forged[i] = Seal(forged[i], prev)
		prev = &forged[i]
	}

	if v := Verify(forged, nil); !v.Valid {
		t.Fatalf("the forged chain should be internally valid: %v", v.Problems)
	}
	v := Verify(forged, &cp)
	if v.Valid {
		t.Fatal("a checkpoint must catch a rewritten log of the same length")
	}
}

// Delimiter injection: a crafted detail value must not be able to impersonate
// a different record's preimage.
func TestDelimiterInjectionCannotForgeAPreimage(t *testing.T) {
	a := Record{
		Seq: 1, Time: time.Unix(0, 0).UTC(), Type: EventRiskAccepted,
		Subject: "m/v", Actor: "alice",
		Detail:   map[string]string{"k": "v;evil:injected"},
		PrevHash: GenesisHash,
	}
	b := Record{
		Seq: 1, Time: time.Unix(0, 0).UTC(), Type: EventRiskAccepted,
		Subject: "m/v", Actor: "alice",
		Detail:   map[string]string{"k": "v", "evil": "injected"},
		PrevHash: GenesisHash,
	}
	if a.ComputeHash() == b.ComputeHash() {
		t.Fatal("a value containing delimiters must not hash the same as separate fields")
	}
}

func TestEqualsInValueCannotForgeAPreimage(t *testing.T) {
	a := Record{Subject: "m/v", Actor: "alice\ntype=PolicyChanged", PrevHash: GenesisHash}
	b := Record{Subject: "m/v", Actor: "alice", Type: "PolicyChanged", PrevHash: GenesisHash}
	if a.ComputeHash() == b.ComputeHash() {
		t.Fatal("a newline in a value must not be able to forge another field")
	}
}

// Detail is a map; Go randomises map iteration. The hash must not.
func TestHashIsStableAcrossMapOrdering(t *testing.T) {
	r := Record{
		Seq: 1, Time: time.Unix(0, 0).UTC(), Subject: "m/v", Actor: "a",
		PrevHash: GenesisHash,
		Detail: map[string]string{
			"z": "1", "a": "2", "m": "3", "q": "4", "b": "5",
		},
	}
	first := r.ComputeHash()
	for i := 0; i < 50; i++ {
		if r.ComputeHash() != first {
			t.Fatal("hash must not depend on map iteration order")
		}
	}
}

func TestSealLinksSequentially(t *testing.T) {
	chain := build(t, 3)
	if chain[0].PrevHash != GenesisHash {
		t.Fatal("the first record must point at genesis")
	}
	for i := 1; i < len(chain); i++ {
		if chain[i].PrevHash != chain[i-1].Hash {
			t.Fatalf("record %d does not link to its predecessor", i+1)
		}
		if chain[i].Seq != chain[i-1].Seq+1 {
			t.Fatal("sequence numbers must be contiguous")
		}
	}
}

// Timestamps round-trip through storage that drops sub-second precision.
// If Seal did not truncate, a chain would stop verifying after being read back.
func TestSubSecondPrecisionDoesNotBreakVerification(t *testing.T) {
	r := Seal(Record{
		Time:    time.Date(2026, 8, 18, 12, 0, 0, 123456789, time.UTC),
		Type:    EventVerdictIssued,
		Subject: "m/v",
		Actor:   "system",
	}, nil)

	if r.Time.Nanosecond() != 0 {
		t.Fatal("Seal must truncate sub-second precision so storage round-trips verify")
	}
	if Verify([]Record{r}, nil).Valid != true {
		t.Fatal("a sealed record must verify")
	}
}
