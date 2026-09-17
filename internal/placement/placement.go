package placement

import (
	"errors"
	"sort"
)

var ErrInsufficientTargets = errors.New("placement: insufficient healthy targets")

type Target struct {
	ID            string
	FailureDomain string
	Healthy       bool
	Score         int
}

type Plan struct {
	Targets []Target
}

func Select(targets []Target, count int) (Plan, error) {
	if count <= 0 {
		return Plan{}, errors.New("placement: target count must be positive")
	}
	available := make([]Target, 0, len(targets))
	for _, target := range targets {
		if target.Healthy {
			available = append(available, target)
		}
	}
	sort.Slice(available, func(left, right int) bool {
		if available[left].Score != available[right].Score {
			return available[left].Score > available[right].Score
		}
		return available[left].ID < available[right].ID
	})
	selected := make([]Target, 0, count)
	domains := make(map[string]struct{})
	for _, target := range available {
		if len(selected) == count {
			break
		}
		if target.FailureDomain != "" {
			if _, exists := domains[target.FailureDomain]; exists {
				continue
			}
			domains[target.FailureDomain] = struct{}{}
		}
		selected = append(selected, target)
	}
	if len(selected) < count {
		for _, target := range available {
			if len(selected) == count {
				break
			}
			alreadySelected := false
			for _, chosen := range selected {
				if chosen.ID == target.ID {
					alreadySelected = true
					break
				}
			}
			if !alreadySelected {
				selected = append(selected, target)
			}
		}
	}
	if len(selected) < count {
		return Plan{}, ErrInsufficientTargets
	}
	return Plan{Targets: selected}, nil
}
