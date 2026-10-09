package engine

import (
	"sync"
	"testing"
	"time"
)

func TestTcGetClassNumberIsFiniteAndUnique(t *testing.T) {
	e := &Engine{}
	e.mu = &sync.Mutex{}
	e.TcDevClasses = make(map[string]bool)

	seen := map[int]bool{}
	for i := 0; i < 50; i++ {
		done := make(chan int, 1)
		go func() { done <- e.TcGetClassNumber() }()

		select {
		case n := <-done:
			if n < 1 || n > 999 {
				t.Fatalf("class %d out of range", n)
			}
			if seen[n] {
				t.Fatalf("duplicate class %d", n)
			}
			seen[n] = true
		case <-time.After(3 * time.Second):
			t.Fatal("TcGetClassNumber blocked: infinite loop")
		}
	}

	// Freed numbers must become available again.
	e.FreeClassNumber(1)
	seen = map[int]bool{}
	for i := 0; i < 999; i++ {
		done := make(chan int, 1)
		go func() { done <- e.TcGetClassNumber() }()
		select {
		case n := <-done:
			seen[n] = true
		case <-time.After(3 * time.Second):
			t.Fatal("blocked after FreeClassNumber")
		}
	}
	if !seen[1] {
		t.Fatal("freed class 1 was never reused")
	}
}

func TestParseDevClass(t *testing.T) {
	if got := ParseDevClass("1:42"); got != 42 {
		t.Errorf("ParseDevClass(1:42) = %d, want 42", got)
	}
	if got := ParseDevClass("nonsense"); got != 0 {
		t.Errorf("ParseDevClass(nonsense) = %d, want 0", got)
	}
}
