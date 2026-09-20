package mobilecore

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestAndroidTunStack(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  C.TUNStack
	}{{"", C.TunGvisor}, {"gvisor", C.TunGvisor}, {"mips", C.TunMips}} {
		got, err := androidTunStack(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("%q: got %v, %v", tc.input, got, err)
		}
	}
	for _, input := range []string{"system", "mixed", "unknown"} {
		if _, err := androidTunStack(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
		if err := StartWithStack("", "", -1, input); err == "" {
			t.Fatalf("start accepted %q", input)
		}
	}
}
