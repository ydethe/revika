package main

import (
	"context"
	"fmt"

	"github.com/revika/revika/internal/provider"
)

func runLS(ctx context.Context, prov provider.Provider, args []string) error {
	path := ""
	if len(args) > 0 {
		path = args[0]
	}
	item, err := resolve(ctx, prov, path)
	if err != nil {
		return err
	}
	if !item.IsDir {
		fmt.Printf("f %10d %s\n", item.Size, item.Name)
		return nil
	}
	children, err := prov.Enumerate(ctx, item.ID)
	if err != nil {
		return err
	}
	for _, child := range children {
		kind := byte('f')
		if child.IsDir {
			kind = 'd'
		}
		fmt.Printf("%c %10d %s\n", kind, child.Size, child.Name)
	}
	return nil
}
