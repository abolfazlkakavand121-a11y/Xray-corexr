package conf

import (
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/fragment"
)

func TestTLSRecordMaskConfig(t *testing.T) {
	raw, err := tcpmaskLoader.LoadWithID([]byte("{\"splitAt\":2}"), "tls-record")
	if err != nil {
		t.Fatal(err)
	}
	buildable, ok := raw.(Buildable)
	if !ok {
		t.Fatalf("loaded config has type %T, want Buildable", raw)
	}
	message, err := buildable.Build()
	if err != nil {
		t.Fatal(err)
	}
	config, ok := message.(*fragment.Config)
	if !ok {
		t.Fatalf("built config has type %T, want *fragment.Config", message)
	}
	if config.PacketsFrom != -1 || config.PacketsTo != 2 {
		t.Fatalf("unexpected internal config marker: from=%d to=%d", config.PacketsFrom, config.PacketsTo)
	}
}

func TestTLSRecordMaskRecordVersionConfig(t *testing.T) {
	raw, err := tcpmaskLoader.LoadWithID([]byte("{\"recordVersion\":769}"), "tls-record")
	if err != nil {
		t.Fatal(err)
	}
	buildable, ok := raw.(Buildable)
	if !ok {
		t.Fatalf("loaded config has type %T, want Buildable", raw)
	}
	message, err := buildable.Build()
	if err != nil {
		t.Fatal(err)
	}
	config, ok := message.(*fragment.Config)
	if !ok {
		t.Fatalf("built config has type %T, want *fragment.Config", message)
	}
	if config.PacketsFrom != -2 || config.PacketsTo != 769 {
		t.Fatalf("unexpected record-version mode: from=%d version=%d", config.PacketsFrom, config.PacketsTo)
	}
}

func TestTLSRecordMaskRecordVersionRejectsInvalidConfig(t *testing.T) {
	for _, rawJSON := range []string{`{"recordVersion":768}`, `{"recordVersion":772}`, `{"recordVersion":769,"splitAt":2}`} {
		raw, err := tcpmaskLoader.LoadWithID([]byte(rawJSON), "tls-record")
		if err != nil {
			t.Fatal(err)
		}
		buildable, ok := raw.(Buildable)
		if !ok {
			t.Fatalf("loaded config has type %T, want Buildable", raw)
		}
		if _, err := buildable.Build(); err == nil {
			t.Fatalf("expected invalid config to be rejected: %s", rawJSON)
		}
	}
}

func TestTLSRecordMaskDifferentialFragmentVersionsConfig(t *testing.T) {
	raw, err := tcpmaskLoader.LoadWithID([]byte(`{"splitAt":2,"firstFragmentVersion":771,"remainingFragmentVersion":769}`), "tls-record")
	if err != nil {
		t.Fatal(err)
	}
	buildable, ok := raw.(Buildable)
	if !ok {
		t.Fatalf("loaded config has type %T, want Buildable", raw)
	}
	message, err := buildable.Build()
	if err != nil {
		t.Fatal(err)
	}
	config, ok := message.(*fragment.Config)
	if !ok {
		t.Fatalf("built config has type %T, want *fragment.Config", message)
	}
	want := int64(2) | (int64(0x0303) << 10) | (int64(0x0301) << 26)
	if config.PacketsFrom != -4 || config.PacketsTo != want {
		t.Fatalf("unexpected differential version config: from=%d packed=%d want=%d", config.PacketsFrom, config.PacketsTo, want)
	}
}

func TestTLSRecordMaskDifferentialFragmentVersionsRejectInvalidConfig(t *testing.T) {
	for _, rawJSON := range []string{
		`{"firstFragmentVersion":771}`,
		`{"remainingFragmentVersion":769}`,
		`{"firstFragmentVersion":772,"remainingFragmentVersion":769}`,
		`{"firstFragmentVersion":771,"remainingFragmentVersion":768}`,
		`{"splitAt":513,"firstFragmentVersion":771,"remainingFragmentVersion":769}`,
		`{"recordVersion":771,"firstFragmentVersion":771,"remainingFragmentVersion":769}`,
	} {
		raw, err := tcpmaskLoader.LoadWithID([]byte(rawJSON), "tls-record")
		if err != nil {
			t.Fatal(err)
		}
		buildable, ok := raw.(Buildable)
		if !ok {
			t.Fatalf("loaded config has type %T, want Buildable", raw)
		}
		if _, err := buildable.Build(); err == nil {
			t.Fatalf("expected invalid config to be rejected: %s", rawJSON)
		}
	}
}

func TestTLSRecordMaskSNISplitConfig(t *testing.T) {
	for _, test := range []struct {
		name string
		mode int64
	}{
		{name: "before-extension", mode: 1},
		{name: "extension-header", mode: 2},
		{name: "mid-hostname", mode: 3},
		{name: "after-extension", mode: 4},
	} {
		raw, err := tcpmaskLoader.LoadWithID([]byte(`{"sniSplit":"`+test.name+`"}`), "tls-record")
		if err != nil {
			t.Fatal(err)
		}
		buildable, ok := raw.(Buildable)
		if !ok {
			t.Fatalf("loaded config has type %T, want Buildable", raw)
		}
		message, err := buildable.Build()
		if err != nil {
			t.Fatal(err)
		}
		config, ok := message.(*fragment.Config)
		if !ok {
			t.Fatalf("built config has type %T, want *fragment.Config", message)
		}
		if config.PacketsFrom != -3 || config.PacketsTo != test.mode {
			t.Fatalf("unexpected SNI split mode: from=%d mode=%d", config.PacketsFrom, config.PacketsTo)
		}
	}
}

func TestTLSRecordMaskRejectsInvalidSNISplitConfig(t *testing.T) {
	for _, rawJSON := range []string{
		`{"sniSplit":"unknown"}`,
		`{"sniSplit":"after-extension","recordVersion":769}`,
	} {
		raw, err := tcpmaskLoader.LoadWithID([]byte(rawJSON), "tls-record")
		if err != nil {
			t.Fatal(err)
		}
		buildable, ok := raw.(Buildable)
		if !ok {
			t.Fatalf("loaded config has type %T, want Buildable", raw)
		}
		if _, err := buildable.Build(); err == nil {
			t.Fatalf("expected invalid config to be rejected: %s", rawJSON)
		}
	}
}

func TestTLSRecordMaskConfigRejectsInvalidSplit(t *testing.T) {
	raw, err := tcpmaskLoader.LoadWithID([]byte("{\"splitAt\":513}"), "tls-record")
	if err != nil {
		t.Fatal(err)
	}
	buildable, ok := raw.(Buildable)
	if !ok {
		t.Fatalf("loaded config has type %T, want Buildable", raw)
	}
	if _, err := buildable.Build(); err == nil {
		t.Fatal("expected invalid splitAt to be rejected")
	}
}
