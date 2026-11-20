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
