package btf

import (
	"errors"
	"fmt"
	"strings"
	"text/template"
)

var errNestedTooDeep = errors.New("nested too deep")

// Template for the load/store helper for variables.
const loadStoreFuncHelper = `
// {{.MethodName}}{{.VarIntName}} interacts with the provided map to {{.Action}} the value of the {{.VarName}} variable.
// The {{.DatasecIntName}} map for which the {{.TypeName}} structure has been generated must be provided,
// otherwise an error will be returned.
func (b *{{.TypeName}}) {{.MethodName}}{{.VarIntName}}(m *ebpf.Map) error {
	if m.Name() != "{{.DatasecName}}" {
		return fmt.Errorf("wrong map provided to {{.MethodName}}{{.VarIntName}}: expected {{.DatasecName}}, got %s", m.Name())
	}
	return m.{{.MethodName}}At({{.Offset}}, uint32(0), &b.{{.VarIntName}})
}
`

// LoadStoreHelperData hold the needed data to fill the loadStoreFuncHelper template,
// used to generate helper functions for interacting with data sections of the program.
type LoadStoreHelperData struct {
	MethodName     string
	VarName        string
	VarIntName     string
	Action         string
	DatasecIntName string
	DatasecName    string
	TypeName       string
	Offset         uint32
}

// GoFormatter converts a Type to Go syntax.
//
// A zero GoFormatter is valid to use.
type GoFormatter struct {
	w strings.Builder

	// Types present in this map are referred to using the given name if they
	// are encountered when outputting another type.
	Names map[Type]string

	// Identifier is called for each field of struct-like types. By default the
	// field name is used as is.
	Identifier func(string) string

	// EnumIdentifier is called for each element of an enum. By default the
	// name of the enum type is concatenated with Identifier(element).
	EnumIdentifier func(name, element string) string
}

// TypeDeclaration generates a Go type declaration for a BTF type.
func (gf *GoFormatter) TypeDeclaration(name string, typ Type) (string, error) {
	gf.w.Reset()
	if err := gf.writeTypeDecl(name, typ); err != nil {
		return "", err
	}
	return gf.w.String(), nil
}

// TypeHelpers generates Go helpers for a BTF type.
func (gf *GoFormatter) TypeHelpers(name string, typ Type) (string, error) {
	gf.w.Reset()
	if err := gf.writeTypeHelpers(name, typ); err != nil {
		return "", err
	}
	return gf.w.String(), nil
}

func (gf *GoFormatter) identifier(s string) string {
	if gf.Identifier != nil {
		return gf.Identifier(s)
	}

	return s
}

func (gf *GoFormatter) enumIdentifier(name, element string) string {
	if gf.EnumIdentifier != nil {
		return gf.EnumIdentifier(name, element)
	}

	return name + gf.identifier(element)
}

// writeTypeDecl outputs a declaration of the given type.
//
// It encodes https://golang.org/ref/spec#Type_declarations:
//
//	type foo struct { bar uint32; }
//	type bar int32
func (gf *GoFormatter) writeTypeDecl(name string, typ Type) error {
	if name == "" {
		return fmt.Errorf("need a name for type %s", typ)
	}

	typ = skipQualifiers(typ)
	fmt.Fprintf(&gf.w, "type %s ", name)
	if err := gf.writeTypeLit(typ, 0); err != nil {
		return err
	}

	e, ok := typ.(*Enum)
	if !ok || len(e.Values) == 0 {
		return nil
	}

	gf.w.WriteString("; const ( ")
	for _, ev := range e.Values {
		id := gf.enumIdentifier(name, ev.Name)
		var value any
		if e.Signed {
			value = int64(ev.Value)
		} else {
			value = ev.Value
		}
		fmt.Fprintf(&gf.w, "%s %s = %d; ", id, name, value)
	}
	gf.w.WriteString(")")

	return nil
}

// writeTypeHelpers outputs helpers for the given type.
//
// It encodes https://go.dev/ref/spec#Method_declarations:
//
//	func (r *Receiver) FuncName(params ...) (return values...) {...}
func (gf *GoFormatter) writeTypeHelpers(name string, typ Type) error {
	if name == "" {
		return fmt.Errorf("need a name for type %s helpers", typ)
	}

	typ = skipQualifiers(typ)

	var err error
	switch v := skipQualifiers(typ).(type) {
	case *Datasec:
		err = gf.writeDatasecFunc(gf.Names[typ], v)
	default:
		return fmt.Errorf("helpers for type %T: %w", v, ErrNotSupported)
	}

	if err != nil {
		return fmt.Errorf("%s: %w", typ, err)
	}

	return nil
}

// writeType outputs the name of a named type or a literal describing the type.
//
// It encodes https://golang.org/ref/spec#Types.
//
//	foo                  (if foo is a named type)
//	uint32
func (gf *GoFormatter) writeType(typ Type, depth int) error {
	typ = skipQualifiers(typ)

	name := gf.Names[typ]
	if name != "" {
		gf.w.WriteString(name)
		return nil
	}

	return gf.writeTypeLit(typ, depth)
}

// writeTypeLit outputs a literal describing the type.
//
// The function ignores named types.
//
// It encodes https://golang.org/ref/spec#TypeLit.
//
//	struct { bar uint32; }
//	uint32
func (gf *GoFormatter) writeTypeLit(typ Type, depth int) error {
	depth++
	if depth > maxResolveDepth {
		return errNestedTooDeep
	}

	var err error
	switch v := skipQualifiers(typ).(type) {
	case *Int:
		err = gf.writeIntLit(v)

	case *Enum:
		if !v.Signed {
			gf.w.WriteRune('u')
		}
		switch v.Size {
		case 1:
			gf.w.WriteString("int8")
		case 2:
			gf.w.WriteString("int16")
		case 4:
			gf.w.WriteString("int32")
		case 8:
			gf.w.WriteString("int64")
		default:
			err = fmt.Errorf("invalid enum size %d", v.Size)
		}

	case *Typedef:
		err = gf.writeType(v.Type, depth)

	case *Array:
		fmt.Fprintf(&gf.w, "[%d]", v.Nelems)
		err = gf.writeType(v.Type, depth)

	case *Struct:
		err = gf.writeStructLit(v.Size, v.Members, depth)

	case *Union:
		// Always choose the first member to represent the union in Go.
		err = gf.writeStructLit(v.Size, v.Members[:1], depth)

	case *Datasec:
		err = gf.writeDatasecLit(v, depth)

	default:
		return fmt.Errorf("type %T: %w", v, ErrNotSupported)
	}

	if err != nil {
		return fmt.Errorf("%s: %w", typ, err)
	}

	return nil
}

func (gf *GoFormatter) writeIntLit(i *Int) error {
	bits := i.Size * 8
	switch i.Encoding {
	case Bool:
		if i.Size != 1 {
			return fmt.Errorf("bool with size %d", i.Size)
		}
		gf.w.WriteString("bool")
	case Char:
		if i.Size != 1 {
			return fmt.Errorf("char with size %d", i.Size)
		}
		// BTF doesn't have a way to specify the signedness of a char. Assume
		// we are dealing with unsigned, since this works nicely with []byte
		// in Go code.
		fallthrough
	case Unsigned, Signed:
		stem := "uint"
		if i.Encoding == Signed {
			stem = "int"
		}
		if i.Size > 8 {
			fmt.Fprintf(&gf.w, "[%d]byte /* %s%d */", i.Size, stem, i.Size*8)
		} else {
			fmt.Fprintf(&gf.w, "%s%d", stem, bits)
		}
	default:
		return fmt.Errorf("can't encode %s", i.Encoding)
	}
	return nil
}

func (gf *GoFormatter) writeStructLit(size uint32, members []Member, depth int) error {
	gf.w.WriteString("struct { ")

	prevOffset := uint32(0)
	skippedBitfield := false
	for i, m := range members {
		if m.BitfieldSize > 0 {
			skippedBitfield = true
			continue
		}

		offset := m.Offset.Bytes()
		if n := offset - prevOffset; skippedBitfield && n > 0 {
			fmt.Fprintf(&gf.w, "_ [%d]byte /* unsupported bitfield */; ", n)
		} else {
			gf.writePadding(n)
		}

		fieldSize, err := Sizeof(m.Type)
		if err != nil {
			return fmt.Errorf("field %d: %w", i, err)
		}

		prevOffset = offset + uint32(fieldSize)
		if prevOffset > size {
			return fmt.Errorf("field %d of size %d exceeds type size %d", i, fieldSize, size)
		}

		if err := gf.writeStructField(m, depth); err != nil {
			return fmt.Errorf("field %d: %w", i, err)
		}
	}

	gf.writePadding(size - prevOffset)
	gf.w.WriteString("}")
	return nil
}

func (gf *GoFormatter) writeStructField(m Member, depth int) error {
	if m.BitfieldSize > 0 {
		return fmt.Errorf("bitfields are not supported")
	}
	if m.Offset%8 != 0 {
		return fmt.Errorf("unsupported offset %d", m.Offset)
	}

	if m.Name == "" {
		// Special case a nested anonymous union like
		//     struct foo { union { int bar; int baz }; }
		// by replacing the whole union with its first member.
		union, ok := m.Type.(*Union)
		if !ok {
			return fmt.Errorf("anonymous fields are not supported")

		}

		if len(union.Members) == 0 {
			return errors.New("empty anonymous union")
		}

		depth++
		if depth > maxResolveDepth {
			return errNestedTooDeep
		}

		m := union.Members[0]
		size, err := Sizeof(m.Type)
		if err != nil {
			return err
		}

		if err := gf.writeStructField(m, depth); err != nil {
			return err
		}

		gf.writePadding(union.Size - uint32(size))
		return nil

	}

	fmt.Fprintf(&gf.w, "%s ", gf.identifier(m.Name))

	if err := gf.writeType(m.Type, depth); err != nil {
		return err
	}

	gf.w.WriteString("; ")
	return nil
}

func (gf *GoFormatter) writeDatasecLit(ds *Datasec, depth int) error {
	gf.w.WriteString("struct { ")

	prevOffset := uint32(0)
	for i, vsi := range ds.Vars {
		v, ok := vsi.Type.(*Var)
		if !ok {
			return fmt.Errorf("can't format %s as part of data section", vsi.Type)
		}

		if v.Linkage != GlobalVar {
			// Ignore static, extern, etc. for now.
			continue
		}

		if v.Name == "" {
			return fmt.Errorf("variable %d: empty name", i)
		}

		gf.writePadding(vsi.Offset - prevOffset)
		prevOffset = vsi.Offset + vsi.Size

		fmt.Fprintf(&gf.w, "%s ", gf.identifier(v.Name))

		if err := gf.writeType(v.Type, depth); err != nil {
			return fmt.Errorf("variable %d: %w", i, err)
		}

		gf.w.WriteString("; ")
	}

	gf.writePadding(ds.Size - prevOffset)
	gf.w.WriteString("}")
	return nil
}

func (gf *GoFormatter) writeDatasecFunc(typeName string, ds *Datasec) error {

	tmpl, err := template.New("helper").Parse(loadStoreFuncHelper)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	prevOffset := uint32(0)
	for i, vsi := range ds.Vars {
		v, ok := vsi.Type.(*Var)

		if !ok {
			return fmt.Errorf("can't format %s as part of data section", vsi.Type)
		}

		if v.Linkage != GlobalVar {
			// Ignore static, extern, etc. for now.
			continue
		}

		if v.Name == "" {
			return fmt.Errorf("variable %d: empty name", i)
		}

		for _, hName := range []string{"Load", "Store"} {
			data := LoadStoreHelperData{
				MethodName:     hName,
				VarName:        v.Name,
				VarIntName:     gf.identifier(v.Name),
				Action:         strings.ToLower(hName),
				DatasecIntName: gf.identifier(ds.Name),
				DatasecName:    ds.Name,
				TypeName:       typeName,
				Offset:         prevOffset,
			}

			if err := tmpl.Execute(&gf.w, data); err != nil {
				return fmt.Errorf("failed to execute template for %s%s: %w", hName, data.VarIntName, err)
			}
		}

		prevOffset = vsi.Offset + vsi.Size
	}

	return nil
}

func (gf *GoFormatter) writePadding(bytes uint32) {
	if bytes > 0 {
		fmt.Fprintf(&gf.w, "_ [%d]byte; ", bytes)
	}
}

func skipQualifiers(typ Type) Type {
	result := typ
	for depth := 0; depth <= maxResolveDepth; depth++ {
		switch v := (result).(type) {
		case qualifier:
			result = v.qualify()
		default:
			return result
		}
	}
	return &cycle{typ}
}
