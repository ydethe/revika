//go:build cgo

package internal

import "testing"

func TestCgoMustBeDisabled(t *testing.T) {
	t.Fatal("revika generic packages must be tested and built with CGO_ENABLED=0")
}
