package config

import "reflect"

type configCloneVisit struct {
	typ reflect.Type
	ptr uintptr
	len int
	cap int
}

// cloneConfigValue copies every mutable reference reachable through the
// exported config fields, preserving pointer and map aliases within the copy.
// Struct values are copied first so compiler-private metadata survives; those
// private fields are compile-time diagnostics and are immutable after compile.
func cloneConfigValue(v reflect.Value, seen map[configCloneVisit]reflect.Value) reflect.Value {
	if !v.IsValid() {
		return v
	}

	t := v.Type()
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		key := configCloneVisit{typ: t, ptr: v.Pointer()}
		if cloned, ok := seen[key]; ok {
			return cloned
		}
		out := reflect.New(t.Elem())
		seen[key] = out
		out.Elem().Set(cloneConfigValue(v.Elem(), seen))
		return out
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.New(t).Elem()
		out.Set(cloneConfigValue(v.Elem(), seen))
		return out
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		key := configCloneVisit{typ: t, ptr: v.Pointer()}
		if cloned, ok := seen[key]; ok {
			return cloned
		}
		out := reflect.MakeMapWithSize(t, v.Len())
		seen[key] = out
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(cloneConfigValue(iter.Key(), seen), cloneConfigValue(iter.Value(), seen))
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		key := configCloneVisit{typ: t, ptr: v.Pointer(), len: v.Len(), cap: v.Cap()}
		if cloned, ok := seen[key]; ok {
			return cloned
		}
		out := reflect.MakeSlice(t, v.Len(), v.Len())
		seen[key] = out
		for i := range v.Len() {
			out.Index(i).Set(cloneConfigValue(v.Index(i), seen))
		}
		return out
	case reflect.Struct:
		out := reflect.New(t).Elem()
		out.Set(v)
		for i := range v.NumField() {
			if t.Field(i).PkgPath != "" {
				continue
			}
			out.Field(i).Set(cloneConfigValue(v.Field(i), seen))
		}
		return out
	case reflect.Array:
		out := reflect.New(t).Elem()
		out.Set(v)
		for i := range v.Len() {
			out.Index(i).Set(cloneConfigValue(v.Index(i), seen))
		}
		return out
	default:
		return v
	}
}
