package profile

import (
	"strings"
	"testing"
)

func TestExportJSONOmitsSecretsByDefault(t *testing.T) {
	p := ready()
	data, err := ExportJSON(p, false)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, p.XAuthPassword) || strings.Contains(text, p.PSK) {
		t.Fatal("exportação padrão não deve conter segredos")
	}
	imported, err := ImportJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Name != p.Name || imported.XAuthPassword != "" || imported.PSK != "" {
		t.Fatalf("perfil importado inesperado: %#v", imported)
	}
}

func TestExportJSONIncludesSecretsWhenRequested(t *testing.T) {
	p := ready()
	data, err := ExportJSON(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), p.XAuthPassword) || !strings.Contains(string(data), p.PSK) {
		t.Fatal("exportação explícita deve conter segredos")
	}
	imported, err := ImportJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if imported.XAuthPassword != p.XAuthPassword || imported.PSK != p.PSK {
		t.Fatal("segredos não foram preservados na importação")
	}
}
