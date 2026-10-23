package main

import "testing"

func TestEqualStringsBoundaries(t *testing.T) {
	cases := []struct {
		name        string
		left, right []string
		want        bool
	}{
		{"nil", nil, nil, true}, {"empty", nil, []string{}, true},
		{"short right", []string{"a"}, nil, false}, {"short left", nil, []string{"a"}, false},
		{"equal", []string{"a", "b"}, []string{"a", "b"}, true},
		{"different", []string{"a", "b"}, []string{"a", "c"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := equalStrings(tc.left, tc.right); got != tc.want {
				t.Fatalf("equalStrings = %v, want %v", got, tc.want)
			}
		})
	}
}
