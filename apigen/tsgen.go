package main

import (
	"fmt"
	"go/types"
	"os"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// typeKey identifies a named type by its package path and type name.
type typeKey struct {
	Pkg  string // full import path, e.g. "github.com/painscaler/painscaler/internal"
	Name string // type name, e.g. "Index"
}

// tsTypeInfo is the collected information about a named type for TS emission.
type tsTypeInfo struct {
	Key    typeKey
	Kind   string    // "struct", "alias", "enum"
	Fields []tsField // for structs
	Alias  string    // for type aliases
}

type tsField struct {
	Name     string // TS property name (respects json tag)
	Type     string // TS type expression
	Optional bool
}

// defaultPkgPath is the Go package containing app.go. Unqualified Go type
// references (e.g. bare "About") resolve here.
const defaultPkgPath = "github.com/painscaler/painscaler/internal/server"

// generateTS walks types referenced by the routes and emits a TypeScript file
// matching the wails-style nested-namespace layout.
func generateTS(routes []route, srcImports map[string]string, outPath string) error {
	// collect seed type refs: pkgSelector.TypeName pairs from route params/returns
	type ref struct {
		sel  string // package selector as it appears in ui/app.go
		name string
	}
	seeds := map[ref]struct{}{}

	addType := func(goType string) {
		t := strings.TrimPrefix(goType, "*")
		t = strings.TrimPrefix(t, "[]")
		t = strings.TrimPrefix(t, "*")
		// skip primitives
		switch t {
		case "string", "bool", "int", "int8", "int16", "int32", "int64",
			"uint", "uint8", "uint16", "uint32", "uint64", "float32", "float64",
			"byte", "rune", "error", "any":
			return
		}
		sel, name, ok := strings.Cut(t, ".")
		if !ok {
			// bare type -- resolves against default package (ui)
			seeds[ref{sel: "", name: t}] = struct{}{}
			return
		}
		seeds[ref{sel: sel, name: name}] = struct{}{}
	}

	for _, r := range routes {
		for _, p := range r.Params {
			addType(p.GoType)
		}
		for _, rt := range r.Returns {
			if rt == "error" {
				continue
			}
			addType(rt)
		}
	}

	// build list of packages to load: those referenced by the seeds.
	pkgPaths := map[string]bool{}
	for s := range seeds {
		if s.sel == "" {
			pkgPaths[defaultPkgPath] = true
			continue
		}
		if path, ok := srcImports[s.sel]; ok {
			pkgPaths[path] = true
		} else {
			return fmt.Errorf("ts gen: unknown package selector %q (not imported by ui/app.go)", s.sel)
		}
	}

	pkgList := make([]string, 0, len(pkgPaths))
	for p := range pkgPaths {
		pkgList = append(pkgList, p)
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedDeps | packages.NeedImports | packages.NeedSyntax | packages.NeedFiles,
	}
	pkgs, err := packages.Load(cfg, pkgList...)
	if err != nil {
		return fmt.Errorf("packages.Load: %w", err)
	}

	// index every loaded package (including deps) by import path
	pkgByPath := map[string]*packages.Package{}
	var indexPkg func(p *packages.Package)
	indexPkg = func(p *packages.Package) {
		if p == nil || pkgByPath[p.PkgPath] != nil {
			return
		}
		pkgByPath[p.PkgPath] = p
		for _, ip := range p.Imports {
			indexPkg(ip)
		}
	}
	for _, p := range pkgs {
		indexPkg(p)
	}

	// BFS over typeKeys, building tsTypeInfo for each named struct/alias.
	worklist := []typeKey{}
	for s := range seeds {
		path := defaultPkgPath
		if s.sel != "" {
			path = srcImports[s.sel]
		}
		worklist = append(worklist, typeKey{Pkg: path, Name: s.name})
	}

	seen := map[typeKey]*tsTypeInfo{}

	for len(worklist) > 0 {
		k := worklist[0]
		worklist = worklist[1:]
		if _, ok := seen[k]; ok {
			continue
		}
		p, ok := pkgByPath[k.Pkg]
		if !ok || p.Types == nil {
			// unknown package -- emit empty interface so output compiles
			seen[k] = &tsTypeInfo{Key: k, Kind: "struct"}
			continue
		}
		obj := p.Types.Scope().Lookup(k.Name)
		if obj == nil {
			seen[k] = &tsTypeInfo{Key: k, Kind: "struct"}
			continue
		}
		named, ok := obj.Type().(*types.Named)
		if !ok {
			// non-named type (unlikely for scope lookup) -- skip
			seen[k] = &tsTypeInfo{Key: k, Kind: "alias", Alias: "unknown"}
			continue
		}

		info := &tsTypeInfo{Key: k}
		seen[k] = info

		switch u := named.Underlying().(type) {
		case *types.Struct:
			info.Kind = "struct"
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				tag := u.Tag(i)
				jsonName, omit, skip := parseJSONTag(tag, f.Name())
				if skip || !f.Exported() {
					continue
				}
				tsType, deps := goTypeToTS(f.Type())
				for _, d := range deps {
					if _, ok := seen[d]; !ok {
						worklist = append(worklist, d)
					}
				}
				info.Fields = append(info.Fields, tsField{
					Name:     jsonName,
					Type:     tsType,
					Optional: omit,
				})
			}
		default:
			info.Kind = "alias"
			tsType, deps := goTypeToTS(named.Underlying())
			for _, d := range deps {
				if _, ok := seen[d]; !ok {
					worklist = append(worklist, d)
				}
			}
			info.Alias = tsType
		}
	}

	return emitTS(seen, outPath)
}

// parseJSONTag returns (jsName, omitempty, skip).
func parseJSONTag(tag, fallback string) (string, bool, bool) {
	if tag == "" {
		return fallback, false, false
	}
	st := reflect.StructTag(tag)
	j := st.Get("json")
	if j == "-" {
		return "", false, true
	}
	if j == "" {
		return fallback, false, false
	}
	parts := strings.Split(j, ",")
	name := parts[0]
	if name == "" {
		name = fallback
	}
	omit := false
	for _, p := range parts[1:] {
		if p == "omitempty" {
			omit = true
		}
	}
	return name, omit, false
}

// goTypeToTS converts a go/types.Type to a TS type expression, collecting
// named-type dependencies to enqueue.
func goTypeToTS(t types.Type) (string, []typeKey) {
	var deps []typeKey
	var rec func(t types.Type) string
	rec = func(t types.Type) string {
		switch x := t.(type) {
		case *types.Basic:
			return basicToTS(x)
		case *types.Pointer:
			return rec(x.Elem())
		case *types.Slice:
			// []byte -> string (base64 in JSON)
			if b, ok := x.Elem().(*types.Basic); ok && b.Kind() == types.Byte {
				return "string"
			}
			return rec(x.Elem()) + "[]"
		case *types.Array:
			if b, ok := x.Elem().(*types.Basic); ok && b.Kind() == types.Byte {
				return "string"
			}
			return rec(x.Elem()) + "[]"
		case *types.Map:
			k := rec(x.Key())
			if k != "string" && k != "number" {
				k = "string"
			}
			return "Record<" + k + ", " + rec(x.Elem()) + ">"
		case *types.Named:
			obj := x.Obj()
			if obj.Pkg() == nil {
				// builtin like error
				if obj.Name() == "error" {
					return "string"
				}
				return "unknown"
			}
			pkgPath := obj.Pkg().Path()
			name := obj.Name()
			// special cases
			if pkgPath == "time" && name == "Time" {
				return "string"
			}
			sel := lastPathSegment(pkgPath)
			deps = append(deps, typeKey{Pkg: pkgPath, Name: name})
			return sel + "." + name
		case *types.Interface:
			return "any"
		case *types.Struct:
			// anonymous struct -- flatten inline
			var sb strings.Builder
			sb.WriteString("{ ")
			for i := 0; i < x.NumFields(); i++ {
				f := x.Field(i)
				jsonName, omit, skip := parseJSONTag(x.Tag(i), f.Name())
				if skip || !f.Exported() {
					continue
				}
				sb.WriteString(jsonName)
				if omit {
					sb.WriteString("?")
				}
				sb.WriteString(": ")
				sb.WriteString(rec(f.Type()))
				sb.WriteString("; ")
			}
			sb.WriteString("}")
			return sb.String()
		case *types.Chan, *types.Signature:
			return "unknown"
		default:
			return "unknown"
		}
	}
	return rec(t), deps
}

func basicToTS(b *types.Basic) string {
	switch b.Kind() {
	case types.Bool:
		return "boolean"
	case types.String:
		return "string"
	case types.Int, types.Int8, types.Int16, types.Int32, types.Int64,
		types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64,
		types.Uintptr, types.Float32, types.Float64,
		types.UntypedInt, types.UntypedFloat, types.UntypedRune:
		return "number"
	case types.UnsafePointer:
		return "unknown"
	}
	if b.Info()&types.IsNumeric != 0 {
		return "number"
	}
	if b.Info()&types.IsString != 0 {
		return "string"
	}
	if b.Info()&types.IsBoolean != 0 {
		return "boolean"
	}
	return "unknown"
}

func lastPathSegment(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return p
	}
	return p[i+1:]
}

// goTypeStringToTS converts a Go type expression (as produced by exprToString)
// into a TS type expression. Returns the TS string and the set of namespaces
// referenced (so the caller can emit type imports).
func goTypeStringToTS(goType string) (string, []string) {
	var refs []string
	var rec func(t string) string
	rec = func(t string) string {
		t = strings.TrimPrefix(t, "*")
		if inner, ok := strings.CutPrefix(t, "[]"); ok {
			return rec(inner) + "[]"
		}
		t = strings.TrimPrefix(t, "*")
		switch t {
		case "string":
			return "string"
		case "bool":
			return "boolean"
		case "int", "int8", "int16", "int32", "int64",
			"uint", "uint8", "uint16", "uint32", "uint64",
			"float32", "float64", "byte", "rune":
			return "number"
		case "error":
			return "string"
		case "any", "interface{}":
			return "any"
		}
		sel, name, ok := strings.Cut(t, ".")
		if !ok {
			// bare type -- default package (emitted as namespace matching defaultPkgPath)
			ns := lastPathSegment(defaultPkgPath)
			refs = append(refs, ns)
			return ns + "." + t
		}
		refs = append(refs, sel)
		return sel + "." + name
	}
	return rec(goType), refs
}

// tsClient emits a typed TS fetch client: one named export per route.
type tsRoute struct {
	FuncName  string
	Method    string
	URL       string // TS template literal or plain string
	HasBody   bool
	BodyArg   string // TS arg name for body payload, or ""
	SigParams string // "name: Type, name2: Type2"
	ReturnTS  string // TS return type expression (without Promise<>)
	IsVoid    bool
}

func buildTSRoutes(routes []route) ([]tsRoute, []string) {
	refSet := map[string]bool{}
	out := make([]tsRoute, 0, len(routes))

	addRef := func(rs []string) {
		for _, r := range rs {
			refSet[r] = true
		}
	}

	for _, r := range routes {
		tr := tsRoute{FuncName: r.FuncName, Method: r.Method}

		// build URL with real param names
		path := r.RoutePath
		path = pathParamRe.ReplaceAllStringFunc(path, func(m string) string {
			name := pathParamRe.FindStringSubmatch(m)[1]
			return "${" + name + "}"
		})

		var queryParts []string
		var sigParts []string
		for _, p := range r.Params {
			if p.Source == "header" {
				continue
			}
			tsType, refs := goTypeStringToTS(p.GoType)
			addRef(refs)
			sigParts = append(sigParts, p.GoName+": "+tsType)
			if p.Source == "query" {
				queryParts = append(queryParts, p.QueryKey+"=${encodeURIComponent(String("+p.GoName+"))}")
			}
			if p.Source == "body" {
				tr.HasBody = true
				tr.BodyArg = p.GoName
			}
		}
		tr.SigParams = strings.Join(sigParts, ", ")

		url := path
		if len(queryParts) > 0 {
			url = path + "?" + strings.Join(queryParts, "&")
		}
		if strings.Contains(url, "${") {
			tr.URL = "`" + url + "`"
		} else {
			tr.URL = "'" + url + "'"
		}

		// return type
		nonErr := ""
		for _, rt := range r.Returns {
			if rt != "error" {
				nonErr = rt
				break
			}
		}
		if nonErr == "" {
			tr.ReturnTS = "void"
			tr.IsVoid = true
		} else {
			rts, refs := goTypeStringToTS(nonErr)
			addRef(refs)
			tr.ReturnTS = rts
		}

		out = append(out, tr)
	}

	refs := make([]string, 0, len(refSet))
	for r := range refSet {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	return out, refs
}

func generateTSClient(routes []route, outPath string) error {
	trs, refs := buildTSRoutes(routes)

	var sb strings.Builder
	sb.WriteString("// Code generated by apigen; DO NOT EDIT.\n")
	sb.WriteString("/* eslint-disable */\n\n")
	if len(refs) > 0 {
		fmt.Fprintf(&sb, "import type { %s } from './models.gen';\n\n", strings.Join(refs, ", "))
	}
	sb.WriteString(`async function _fetch<T>(url: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(url, opts);
  if (!r.ok) {
    const text = await r.text();
    throw new Error(text || r.statusText);
  }
  if (r.status === 204) return undefined as T;
  return (await r.json()) as T;
}

`)

	for _, tr := range trs {
		ret := "Promise<" + tr.ReturnTS + ">"
		fmt.Fprintf(&sb, "export function %s(%s): %s {\n", tr.FuncName, tr.SigParams, ret)
		switch {
		case tr.HasBody:
			fmt.Fprintf(&sb, "  return _fetch(%s, {\n", tr.URL)
			fmt.Fprintf(&sb, "    method: '%s',\n", tr.Method)
			sb.WriteString("    headers: { 'Content-Type': 'application/json' },\n")
			fmt.Fprintf(&sb, "    body: JSON.stringify(%s),\n", tr.BodyArg)
			sb.WriteString("  });\n")
		case tr.Method == "GET":
			fmt.Fprintf(&sb, "  return _fetch(%s);\n", tr.URL)
		default:
			fmt.Fprintf(&sb, "  return _fetch(%s, { method: '%s' });\n", tr.URL, tr.Method)
		}
		sb.WriteString("}\n\n")
	}

	return os.WriteFile(outPath, []byte(sb.String()), 0644)
}

// emitTS writes the collected types grouped by package as nested namespaces.
func emitTS(seen map[typeKey]*tsTypeInfo, outPath string) error {
	// group by namespace selector (last path segment)
	byNs := map[string][]*tsTypeInfo{}
	for _, info := range seen {
		sel := lastPathSegment(info.Key.Pkg)
		byNs[sel] = append(byNs[sel], info)
	}

	namespaces := make([]string, 0, len(byNs))
	for n := range byNs {
		namespaces = append(namespaces, n)
	}
	sort.Strings(namespaces)

	var sb strings.Builder
	sb.WriteString("// Code generated by apigen; DO NOT EDIT.\n")
	sb.WriteString("/* eslint-disable */\n\n")

	for _, ns := range namespaces {
		infos := byNs[ns]
		sort.Slice(infos, func(i, j int) bool { return infos[i].Key.Name < infos[j].Key.Name })
		fmt.Fprintf(&sb, "export namespace %s {\n", ns)
		for _, info := range infos {
			switch info.Kind {
			case "struct":
				fmt.Fprintf(&sb, "\texport class %s {\n", info.Key.Name)
				for _, f := range info.Fields {
					opt := ""
					if f.Optional {
						opt = "?"
					}
					fmt.Fprintf(&sb, "\t\t%s%s: %s;\n", f.Name, opt, f.Type)
				}
				sb.WriteString("\n\t\tstatic createFrom(source: any = {}) {\n")
				fmt.Fprintf(&sb, "\t\t\treturn new %s(source);\n", info.Key.Name)
				sb.WriteString("\t\t}\n\n")
				sb.WriteString("\t\tconstructor(source: any = {}) {\n")
				sb.WriteString("\t\t\tif ('string' === typeof source) source = JSON.parse(source);\n")
				for _, f := range info.Fields {
					fmt.Fprintf(&sb, "\t\t\tthis[%q] = source[%q];\n", f.Name, f.Name)
				}
				sb.WriteString("\t\t}\n")
				sb.WriteString("\t}\n")
			case "alias":
				fmt.Fprintf(&sb, "\texport type %s = %s;\n", info.Key.Name, info.Alias)
			}
		}
		sb.WriteString("}\n\n")
	}

	return os.WriteFile(outPath, []byte(sb.String()), 0644)
}
