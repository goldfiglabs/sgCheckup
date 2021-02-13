package multirange_test

import (
	"testing"

	"goldfiglabs.com/sgcheckup/internal/multirange"
)

func TestConstructMultiRange(t *testing.T) {
	cases := []string{
		"[22,24]",
		"[22,22],[23,24]",
		"[22,23),[23,24),[23,24]",
	}
	want := "[22,24]"
	for _, testcase := range cases {
		mr, err := multirange.FromString(testcase)
		if err != nil {
			t.Errorf("Failed %v", err)
		}
		got := mr.ToString()
		if got != want {
			t.Errorf("MultiRange(%v) = %v, want %v", testcase, got, want)
		}
	}
}

func TestRemoveElement(t *testing.T) {
	cases := []struct {
		input string
		el    int
		want  string
	}{
		{
			input: "[22,22]",
			el:    22,
			want:  "",
		},
		{
			input: "[22,23]",
			el:    22,
			want:  "[23,23]",
		},
		{
			input: "[22,23]",
			el:    24,
			want:  "[22,23]",
		},
		{
			input: "[0,5],[10,15]",
			el:    12,
			want:  "[0,5],[10,11],[13,15]",
		},
		{
			input: "[0,5],[10,15],[20,24]",
			el:    12,
			want:  "[0,5],[10,11],[13,15],[20,24]",
		},
	}
	for _, testcase := range cases {
		mr, err := multirange.FromString(testcase.input)
		if err != nil {
			t.Errorf("Failed %v", err)
		}
		mr.RemoveElement(testcase.el)
		got := mr.ToString()
		if got != testcase.want {
			t.Errorf("MultiRange(%v).RemoveElement(%v) = %v, want %v",
				testcase.input, testcase.input, got, testcase.want)
		}
	}
}
