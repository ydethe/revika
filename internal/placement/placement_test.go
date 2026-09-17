package placement

import "testing"

func TestSelectPrefersHealthyDistinctDomains(t *testing.T) {
	plan, err := Select([]Target{
		{ID: "a", FailureDomain: "one", Healthy: true, Score: 10},
		{ID: "b", FailureDomain: "one", Healthy: true, Score: 9},
		{ID: "c", FailureDomain: "two", Healthy: true, Score: 8},
		{ID: "d", FailureDomain: "three", Healthy: false, Score: 100},
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Targets[0].ID != "a" || plan.Targets[1].ID != "c" {
		t.Fatalf("selected targets = %#v", plan.Targets)
	}
}
