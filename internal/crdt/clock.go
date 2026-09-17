package crdt

import (
	"encoding/json"
)

type Relation uint8

const (
	Equal Relation = iota
	Before
	After
	Concurrent
)

type Clock map[string]uint64

func (clock Clock) Clone() Clock {
	clone := make(Clock, len(clock))
	for actor, counter := range clock {
		clone[actor] = counter
	}
	return clone
}

func (clock Clock) Tick(actor string) Clock {
	result := clock.Clone()
	result[actor]++
	return result
}

func (clock Clock) Merge(other Clock) Clock {
	result := clock.Clone()
	for actor, counter := range other {
		if counter > result[actor] {
			result[actor] = counter
		}
	}
	return result
}

func (clock Clock) Compare(other Clock) Relation {
	less, greater := false, false
	actors := make(map[string]struct{}, len(clock)+len(other))
	for actor := range clock {
		actors[actor] = struct{}{}
	}
	for actor := range other {
		actors[actor] = struct{}{}
	}
	for actor := range actors {
		if clock[actor] < other[actor] {
			less = true
		}
		if clock[actor] > other[actor] {
			greater = true
		}
	}
	switch {
	case less && greater:
		return Concurrent
	case less:
		return Before
	case greater:
		return After
	default:
		return Equal
	}
}

func (clock Clock) MarshalBinary() ([]byte, error) { return json.Marshal(clock) }

func ParseClock(data []byte) (Clock, error) {
	var clock Clock
	if err := json.Unmarshal(data, &clock); err != nil {
		return nil, err
	}
	return clock, nil
}
