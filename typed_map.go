package ebpf

import (
	"github.com/cilium/ebpf/btf"
)

// Typed MapIterator
type MapIteratorT[K, V any] MapIterator

func (m *MapIteratorT[K, V]) Err() error { return reinterp[MapIterator](m).Err() }
func (m *MapIteratorT[K, V]) Next() bool {
	var key K
	var val V
	return reinterp[MapIterator](m).Next(&key, &val)
}

// Typed MapSpec
type MapSpecT[T any] MapSpec

func (ms *MapSpecT[T]) String() string { return reinterp[MapSpec](ms).String() }
func (ms *MapSpecT[T]) Copy() *MapSpecT[T] {
	return reinterp[MapSpecT[T]](reinterp[MapSpec](ms).Copy())
}

// TypedMap
type MapT[K, V any] Map

func (m *MapT[K, V]) ValueSize() uint32            { return reinterp[Map](m).ValueSize() }
func (m *MapT[K, V]) Type() MapType                { return reinterp[Map](m).Type() }
func (m *MapT[K, V]) String() string               { return reinterp[Map](m).String() }
func (m *MapT[K, V]) MaxEntries() uint32           { return reinterp[Map](m).MaxEntries() }
func (m *MapT[K, V]) Close() error                 { return reinterp[Map](m).Close() }
func (m *MapT[K, V]) Info() (*MapInfo, error)      { return reinterp[Map](m).Info() }
func (m *MapT[K, V]) Handle() (*btf.Handle, error) { return reinterp[Map](m).Handle() }
func (m *MapT[K, V]) Freeze() error                { return reinterp[Map](m).Freeze() }
func (m *MapT[K, V]) Flags() uint32                { return reinterp[Map](m).Flags() }
func (m *MapT[K, V]) FD() int                      { return reinterp[Map](m).FD() }
func (m *MapT[K, V]) IsPinned() bool               { return reinterp[Map](m).IsPinned() }
func (m *MapT[K, V]) KeySize() uint32              { return reinterp[Map](m).KeySize() }
func (m *MapT[K, V]) Pin(filename string) error    { return reinterp[Map](m).Pin(filename) }
func (m *MapT[K, V]) Unpin() error                 { return reinterp[Map](m).Unpin() }
func (m *MapT[K, V]) Memory() (*Memory, error)     { return reinterp[Map](m).Memory() }
func (m *MapT[K, V]) Clone() (*MapT[K, V], error) {
	mc, err := reinterp[Map](m).Clone()
	return reinterp[MapT[K, V]](mc), err
}
func (m *MapT[K, V]) Update(key *K, val *V, flags MapUpdateFlags) error {
	return reinterp[Map](m).Update(key, val, flags)
}
func (m *MapT[K, V]) Put(key *K, val *V) error {
	return reinterp[Map](m).Put(key, val)
}
func (m *MapT[K, V]) Delete(key *K) error {
	return reinterp[Map](m).Delete(key)
}
func (m *MapT[K, V]) LookupBytes(key *K) ([]byte, error) {
	return reinterp[Map](m).LookupBytes(key)
}
func (m *MapT[K, V]) Lookup(key *K) (V, error) {
	var val V
	return val, reinterp[Map](m).Lookup(key, &val)
}
func (m *MapT[K, V]) LookupAndDelete(key *K) (V, error) {
	var val V
	return val, reinterp[Map](m).LookupAndDelete(key, &val)
}
func (m *MapT[K, V]) LookupAndDeleteWithFlags(key *K, flags MapLookupFlags) (V, error) {
	var val V
	return val, reinterp[Map](m).LookupAndDeleteWithFlags(key, &val, flags)
}
func (m *MapT[K, V]) BatchDelete(keys []K, opts *BatchOptions) (int, error) {
	return reinterp[Map](m).BatchDelete(keys, opts)
}
func (m *MapT[K, V]) BatchLookup(cursor *MapBatchCursor, keys []K, opts *BatchOptions) ([]V, int, error) {
	vals := make([]V, len(keys))
	c, err := reinterp[Map](m).BatchLookup(cursor, keys, vals, opts)
	return vals, c, err
}
func (m *MapT[K, V]) BatchUpdate(keys []K, vals []V, opts *BatchOptions) (int, error) {
	return reinterp[Map](m).BatchUpdate(keys, vals, opts)
}
func (m *MapT[K, V]) BatchLookupAndDelete(cursor *MapBatchCursor, keys []K, opts *BatchOptions) ([]V, int, error) {
	vals := make([]V, len(keys))
	c, err := reinterp[Map](m).BatchLookupAndDelete(cursor, keys, vals, opts)
	return vals, c, err
}
func (m *MapT[K, V]) NextKey(key *K) (K, error) {
	var nextKeyOut K
	return nextKeyOut, reinterp[Map](m).NextKey(key, &nextKeyOut)
}
func (m *MapT[K, V]) NextKeyBytes(key *K) ([]byte, error) {
	return reinterp[Map](m).NextKeyBytes(key)
}
func (m *MapT[K, V]) Iterate() *MapIteratorT[K, V] {
	return reinterp[MapIteratorT[K, V]](reinterp[Map](m).Iterate())
}
