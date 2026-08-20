package profile

import (
	"encoding/json"
	"fmt"
)

const exportFormat = "pipersec-profile"

type exportDocument struct {
	Format  string  `json:"format"`
	Version int     `json:"version"`
	Profile Profile `json:"profile"`
}

// ExportJSON serializes a profile for transfer between PiperSec installations.
// Secrets are excluded unless includeSecrets is explicitly true.
func ExportJSON(p Profile, includeSecrets bool) ([]byte, error) {
	if err := p.Validate(includeSecrets); err != nil {
		return nil, fmt.Errorf("validar perfil para exportação: %w", err)
	}
	if !includeSecrets {
		p.XAuthPassword = ""
		p.PSK = ""
	}
	doc := exportDocument{Format: exportFormat, Version: 1, Profile: p}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serializar perfil: %w", err)
	}
	return append(data, '\n'), nil
}

// ImportJSON validates and decodes a profile export. Imported profiles may
// omit secrets; the caller can collect them later through the normal edit flow.
func ImportJSON(data []byte) (Profile, error) {
	var doc exportDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return Profile{}, fmt.Errorf("ler arquivo de importação: %w", err)
	}
	if doc.Format != exportFormat || doc.Version != 1 {
		return Profile{}, fmt.Errorf("formato de exportação PiperSec não suportado")
	}
	if err := doc.Profile.Validate(false); err != nil {
		return Profile{}, fmt.Errorf("validar perfil importado: %w", err)
	}
	return doc.Profile, nil
}
