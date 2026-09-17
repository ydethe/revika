package crdt

import (
	"sort"
)

type ElementID struct {
	Actor   string `json:"actor"`
	Counter uint64 `json:"counter"`
}

type Element struct {
	ID      ElementID `json:"id"`
	After   ElementID `json:"after"`
	Value   rune      `json:"value"`
	Deleted bool      `json:"deleted"`
}

type Operation struct {
	Clock   Clock      `json:"clock"`
	Element *Element   `json:"element,omitempty"`
	Delete  *ElementID `json:"delete,omitempty"`
}

type Text struct {
	Clock    Clock
	Elements map[ElementID]Element
}

func NewText() *Text {
	return &Text{Clock: make(Clock), Elements: make(map[ElementID]Element)}
}

func (text *Text) Insert(actor string, after ElementID, value string) []Operation {
	operations := make([]Operation, 0, len([]rune(value)))
	for _, character := range []rune(value) {
		text.Clock = text.Clock.Tick(actor)
		id := ElementID{Actor: actor, Counter: text.Clock[actor]}
		element := Element{ID: id, After: after, Value: character}
		operation := Operation{Clock: text.Clock.Clone(), Element: &element}
		text.Apply(operation)
		operations = append(operations, operation)
		after = id
	}
	return operations
}

func (text *Text) Delete(ids ...ElementID) []Operation {
	operations := make([]Operation, 0, len(ids))
	for _, id := range ids {
		text.Clock = text.Clock.Tick("delete")
		operation := Operation{Clock: text.Clock.Clone(), Delete: &id}
		text.Apply(operation)
		operations = append(operations, operation)
	}
	return operations
}

func (text *Text) Apply(operation Operation) {
	text.Clock = text.Clock.Merge(operation.Clock)
	if operation.Element != nil {
		if _, exists := text.Elements[operation.Element.ID]; !exists {
			text.Elements[operation.Element.ID] = *operation.Element
		}
	}
	if operation.Delete != nil {
		if element, exists := text.Elements[*operation.Delete]; exists {
			element.Deleted = true
			text.Elements[*operation.Delete] = element
		}
	}
}

func (text *Text) Merge(operations []Operation) {
	for _, operation := range operations {
		text.Apply(operation)
	}
}

func (text *Text) String() string {
	children := make(map[ElementID][]ElementID)
	for id, element := range text.Elements {
		children[element.After] = append(children[element.After], id)
	}
	for parent := range children {
		sort.Slice(children[parent], func(left, right int) bool { return lessID(children[parent][left], children[parent][right]) })
	}
	result := make([]rune, 0, len(text.Elements))
	var visit func(ElementID)
	visit = func(parent ElementID) {
		for _, id := range children[parent] {
			element := text.Elements[id]
			if !element.Deleted {
				result = append(result, element.Value)
			}
			visit(id)
		}
	}
	visit(ElementID{})
	return string(result)
}

func lessID(left, right ElementID) bool {
	if left.Actor == right.Actor {
		return left.Counter < right.Counter
	}
	return left.Actor < right.Actor
}
