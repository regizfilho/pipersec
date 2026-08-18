package main

import "testing"

func TestChildNamesFromConfig(t *testing.T) {
	config := []byte(`connections {
    office {
        children {
            office-1 {
            }
            office-2 {
            }
        }
    }
}
`)
	got := childNamesFromConfig(config)
	if len(got) != 2 || got[0] != "office-1" || got[1] != "office-2" {
		t.Fatalf("got %v", got)
	}
}

func TestChildNamesFromConfigSingleChild(t *testing.T) {
	config := []byte(`connections {
    single {
        children {
            single {
            }
        }
    }
}
`)
	got := childNamesFromConfig(config)
	if len(got) != 1 || got[0] != "single" {
		t.Fatalf("got %v", got)
	}
}
