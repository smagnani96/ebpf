package ebpf

import (
	"github.com/cilium/ebpf/btf"
)

// Typed VariableSpec
type VariableSpecT[T any] VariableSpec

func (v *VariableSpecT[T]) Get() (T, error) {
	var out T
	return out, reinterp[VariableSpec](v).Get(&out)
}
func (vs *VariableSpecT[T]) Set(in T) error { return reinterp[VariableSpec](vs).Set(in) }
func (vs *VariableSpecT[T]) Constant() bool { return reinterp[VariableSpec](vs).Constant() }
func (vs *VariableSpecT[T]) Size() uint64   { return reinterp[VariableSpec](vs).Size() }
func (vs *VariableSpecT[T]) String() string { return reinterp[VariableSpec](vs).String() }
func (vs *VariableSpecT[T]) Type() btf.Type { return reinterp[VariableSpec](vs).Type() }

// Typed Variable
type VariableT[T any] Variable

func (v *VariableT[T]) Get() (T, error) {
	var out T
	return out, reinterp[Variable](v).Get(&out)
}
func (v *VariableT[T]) Set(in T) error { return reinterp[Variable](v).Set(in) }
func (v *VariableT[T]) ReadOnly() bool { return reinterp[Variable](v).ReadOnly() }
func (v *VariableT[T]) Size() uint64   { return reinterp[Variable](v).Size() }
func (v *VariableT[T]) String() string { return reinterp[Variable](v).String() }
func (v *VariableT[T]) Type() btf.Type { return reinterp[Variable](v).Type() }
