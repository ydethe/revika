package main

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/revika/revika/internal/provider"
)

func runRM(ctx context.Context, prov provider.Provider, database *sql.DB, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("rm: expected exactly one path")
	}
	item, err := resolve(ctx, prov, args[0])
	if err != nil {
		return err
	}
	if item.ID == provider.RootID {
		return fmt.Errorf("rm: cannot remove the root")
	}
	ids, err := collectSubtree(ctx, prov, item)
	if err != nil {
		return err
	}
	if err := prov.DeleteItem(ctx, item.ID); err != nil {
		return err
	}
	return deleteFileKeys(database, ids)
}

// collectSubtree returns item's ID plus every descendant's ID, gathered before deletion
// since the tree is gone afterward.
func collectSubtree(ctx context.Context, prov provider.Provider, item provider.Item) ([]provider.ItemID, error) {
	ids := []provider.ItemID{item.ID}
	if !item.IsDir {
		return ids, nil
	}
	children, err := prov.Enumerate(ctx, item.ID)
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		childIDs, err := collectSubtree(ctx, prov, child)
		if err != nil {
			return nil, err
		}
		ids = append(ids, childIDs...)
	}
	return ids, nil
}
