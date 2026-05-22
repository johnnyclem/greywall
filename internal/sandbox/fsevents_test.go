package sandbox

import (
	"fmt"
	"sync"
	"testing"
)

func makeEvent(i int) FsEvent {
	return FsEvent{Ts: fmt.Sprintf("t%d", i), Op: "open_read", Path: fmt.Sprintf("/p/%d", i)}
}

func TestFsEventBuffer_DrainEmpty(t *testing.T) {
	b := NewFsEventBuffer(4)
	events, dropped := b.Drain()
	if events != nil {
		t.Errorf("expected nil events, got %v", events)
	}
	if dropped != 0 {
		t.Errorf("expected dropped=0, got %d", dropped)
	}
}

func TestFsEventBuffer_PushUnderCap(t *testing.T) {
	b := NewFsEventBuffer(4)
	for i := 0; i < 3; i++ {
		b.Push(makeEvent(i))
	}
	events, dropped := b.Drain()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if dropped != 0 {
		t.Errorf("expected dropped=0, got %d", dropped)
	}
	for i, e := range events {
		if e.Path != fmt.Sprintf("/p/%d", i) {
			t.Errorf("event[%d]: expected /p/%d, got %s", i, i, e.Path)
		}
	}
}

func TestFsEventBuffer_PushExactCap(t *testing.T) {
	b := NewFsEventBuffer(4)
	for i := 0; i < 4; i++ {
		b.Push(makeEvent(i))
	}
	events, dropped := b.Drain()
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}
	if dropped != 0 {
		t.Errorf("expected dropped=0, got %d", dropped)
	}
	for i, e := range events {
		if e.Path != fmt.Sprintf("/p/%d", i) {
			t.Errorf("event[%d]: expected /p/%d, got %s", i, i, e.Path)
		}
	}
}

func TestFsEventBuffer_Overflow(t *testing.T) {
	b := NewFsEventBuffer(3)
	// Push 5 events into a cap=3 buffer: 0, 1, 2, 3, 4
	// After overflow, buffer should hold [2, 3, 4] and dropped=2
	for i := 0; i < 5; i++ {
		b.Push(makeEvent(i))
	}
	events, dropped := b.Drain()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if dropped != 2 {
		t.Errorf("expected dropped=2, got %d", dropped)
	}
	want := []string{"/p/2", "/p/3", "/p/4"}
	for i, e := range events {
		if e.Path != want[i] {
			t.Errorf("event[%d]: expected %s, got %s", i, want[i], e.Path)
		}
	}
}

func TestFsEventBuffer_DrainResets(t *testing.T) {
	b := NewFsEventBuffer(3)
	for i := 0; i < 5; i++ {
		b.Push(makeEvent(i))
	}
	if _, dropped := b.Drain(); dropped != 2 {
		t.Fatalf("first drain: expected dropped=2, got %d", dropped)
	}
	// Second drain immediately after: should be empty, dropped reset.
	events, dropped := b.Drain()
	if events != nil || dropped != 0 {
		t.Errorf("expected (nil, 0) after reset, got (%v, %d)", events, dropped)
	}
	// Push two more, drain: should see only those two, dropped=0.
	b.Push(makeEvent(100))
	b.Push(makeEvent(101))
	events, dropped = b.Drain()
	if len(events) != 2 || events[0].Path != "/p/100" || events[1].Path != "/p/101" {
		t.Errorf("post-reset push: unexpected events %v", events)
	}
	if dropped != 0 {
		t.Errorf("post-reset push: expected dropped=0, got %d", dropped)
	}
}

func TestFsEventBuffer_DroppedOnlyNoEvents(t *testing.T) {
	// Drain reports dropped count even if no live events remain after wrap.
	// Push cap+1, then drain: 1 dropped, cap events. Push one more, drain.
	b := NewFsEventBuffer(2)
	for i := 0; i < 3; i++ {
		b.Push(makeEvent(i))
	}
	if _, dropped := b.Drain(); dropped != 1 {
		t.Fatalf("first drain: expected dropped=1, got %d", dropped)
	}
	// Cause more drops with a small ring and no consumer.
	for i := 0; i < 5; i++ {
		b.Push(makeEvent(i))
	}
	events, dropped := b.Drain()
	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
	if dropped != 3 {
		t.Errorf("expected dropped=3, got %d", dropped)
	}
}

func TestFsEventBuffer_ZeroCapacityClamped(t *testing.T) {
	b := NewFsEventBuffer(0)
	b.Push(makeEvent(1))
	b.Push(makeEvent(2)) // drops event 1
	events, dropped := b.Drain()
	if len(events) != 1 || events[0].Path != "/p/2" {
		t.Errorf("expected [/p/2], got %v", events)
	}
	if dropped != 1 {
		t.Errorf("expected dropped=1, got %d", dropped)
	}
}

func TestFsEventBuffer_Len(t *testing.T) {
	b := NewFsEventBuffer(4)
	if b.Len() != 0 {
		t.Errorf("empty buffer: expected Len=0, got %d", b.Len())
	}
	b.Push(makeEvent(0))
	b.Push(makeEvent(1))
	if b.Len() != 2 {
		t.Errorf("after 2 pushes: expected Len=2, got %d", b.Len())
	}
	_, _ = b.Drain()
	if b.Len() != 0 {
		t.Errorf("after drain: expected Len=0, got %d", b.Len())
	}
}

func TestFsEventBuffer_ConcurrentPush(t *testing.T) {
	// Stress: many producers pushing into a small buffer. We don't assert
	// ordering across producers — just that the structure stays consistent
	// (no panics, totals add up).
	b := NewFsEventBuffer(64)
	const producers = 8
	const perProducer = 1000
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				b.Push(makeEvent(p*perProducer + i))
			}
		}(p)
	}
	wg.Wait()

	events, dropped := b.Drain()
	total := uint64(len(events)) + dropped
	if total != producers*perProducer {
		t.Errorf("expected total=%d (events+dropped), got %d (events=%d, dropped=%d)",
			producers*perProducer, total, len(events), dropped)
	}
	if len(events) > 64 {
		t.Errorf("event count %d exceeds capacity 64", len(events))
	}
}
