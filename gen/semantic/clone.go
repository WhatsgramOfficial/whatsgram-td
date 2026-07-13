package semantic

import "github.com/gotd/tl"

func cloneSchema(source *tl.Schema) *tl.Schema {
	if source == nil {
		return nil
	}
	result := &tl.Schema{
		Layer: source.Layer,
	}
	result.Classes = append(result.Classes, source.Classes...)
	result.Definitions = make([]tl.SchemaDefinition, len(source.Definitions))
	for i, schemaDef := range source.Definitions {
		result.Definitions[i] = cloneSchemaDefinition(schemaDef)
	}
	return result
}

func cloneSchemaDefinition(source tl.SchemaDefinition) tl.SchemaDefinition {
	result := source
	result.Annotations = append([]tl.Annotation(nil), source.Annotations...)
	result.Definition.Namespace = append([]string(nil), source.Definition.Namespace...)
	result.Definition.GenericParams = append([]string(nil), source.Definition.GenericParams...)
	result.Definition.Type = cloneTLType(source.Definition.Type)
	result.Definition.Params = make([]tl.Parameter, len(source.Definition.Params))
	for i, parameter := range source.Definition.Params {
		result.Definition.Params[i] = parameter
		result.Definition.Params[i].Type = cloneTLType(parameter.Type)
		if parameter.Flag != nil {
			flag := *parameter.Flag
			result.Definition.Params[i].Flag = &flag
		}
	}
	return result
}

func cloneTLType(source tl.Type) tl.Type {
	result := source
	result.Namespace = append([]string(nil), source.Namespace...)
	if source.GenericArg != nil {
		arg := cloneTLType(*source.GenericArg)
		result.GenericArg = &arg
	}
	return result
}

func mergeSchema(target, overlay *tl.Schema) {
	ids := make(map[uint32]struct{}, len(target.Definitions))
	for _, definition := range target.Definitions {
		ids[definition.Definition.ID] = struct{}{}
	}
	for _, definition := range overlay.Definitions {
		if _, exists := ids[definition.Definition.ID]; exists {
			continue
		}
		target.Definitions = append(target.Definitions, cloneSchemaDefinition(definition))
		ids[definition.Definition.ID] = struct{}{}
	}

	classes := make(map[string]struct{}, len(target.Classes))
	for _, class := range target.Classes {
		classes[class.Name] = struct{}{}
	}
	for _, class := range overlay.Classes {
		if _, exists := classes[class.Name]; exists {
			continue
		}
		target.Classes = append(target.Classes, class)
		classes[class.Name] = struct{}{}
	}
	if target.Layer == 0 {
		target.Layer = overlay.Layer
	}
}
