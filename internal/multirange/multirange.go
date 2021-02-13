package multirange

import (
	"strconv"
	"strings"
)

type intRange struct {
	min int
	max int
}

func (i *intRange) Size() int {
	return i.max - i.min + 1
}

func (i *intRange) ToString() string {
	s := "["
	s += strconv.Itoa(i.min)
	s += ","
	s += strconv.Itoa(i.max)
	s += "]"
	return s
}

func (i *intRange) Humanize() string {
	if i.min == i.max {
		return strconv.Itoa(i.min)
	}
	s := strconv.Itoa(i.min)
	s += "-"
	s += strconv.Itoa(i.max)
	return s
}

func (i *intRange) Remove(el int) []intRange {
	if !i.Contains(el) {
		return []intRange{*i}
	}
	if i.min < el {
		if el < i.max {
			return []intRange{{
				min: i.min,
				max: el - 1,
			}, {
				min: el + 1,
				max: i.max,
			}}
		}
		// el == i.max
		return []intRange{{
			min: i.min,
			max: el - 1,
		}}
	}
	// el == i.min
	if el < i.max {
		return []intRange{{
			min: el + 1,
			max: i.max,
		}}
	}
	// el == i.min == i.max
	return []intRange{}
}

func (i *intRange) Contains(el int) bool {
	return el >= i.min && el <= i.max
}

func (i *intRange) LessThan(other *intRange) bool {
	return i.max < other.min
}

func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}

func min(x, y int) int {
	if x > y {
		return y
	}
	return x
}

func (i *intRange) Overlaps(other *intRange) (overlaps bool, combined *intRange) {
	if i.min < other.min {
		// account for adjacency
		if i.max >= other.min-1 {

		} else {
			return false, nil
		}
	} else if i.min == other.min {
		// definitely overlap
	} else { // i.min > other.min
		// account for adjacency
		if i.min <= other.max+1 {

		} else {
			return false, nil
		}
	}
	min := min(i.min, other.min)
	max := max(i.max, other.max)
	return true, &intRange{
		min: min,
		max: max,
	}
}

func newIntRangeFromString(s string) (*intRange, error) {
	minInclusive := s[0] == '['
	maxInclusive := s[len(s)-1] == ']'
	boundsString := s[1 : len(s)-1]
	bounds := strings.Split(boundsString, ",")
	min, err := strconv.Atoi(bounds[0])
	if err != nil {
		return nil, err
	}
	if !minInclusive {
		min++
	}
	max, err := strconv.Atoi(bounds[1])
	if err != nil {
		return nil, err
	}
	if !maxInclusive {
		max--
	}
	return &intRange{
		min: min,
		max: max,
	}, nil
}

type MultiRange struct {
	ranges []intRange
}

func (m *MultiRange) Size() int {
	sum := 0
	for _, r := range m.ranges {
		sum += r.Size()
	}
	return sum
}

func (m *MultiRange) ToString() string {
	ranges := []string{}
	for _, r := range m.ranges {
		ranges = append(ranges, r.ToString())
	}
	return strings.Join(ranges, ",")
}

func (m *MultiRange) Humanize() string {
	ranges := []string{}
	for _, r := range m.ranges {
		ranges = append(ranges, r.Humanize())
	}
	return strings.Join(ranges, ",")
}

func FromString(s string) (*MultiRange, error) {
	parts := strings.Split(s, ",")
	mr := &MultiRange{[]intRange{}}
	for i := 0; i < len(parts); i += 2 {
		intRange, err := newIntRangeFromString(parts[i] + "," + parts[i+1])
		if err != nil {
			return nil, err
		}
		mr.appendRange(*intRange)
	}
	return mr, nil
}

func (m *MultiRange) appendRange(r intRange) {
	ranges := []intRange{}
	accum := r
	appended := false
	for i, existing := range m.ranges {
		if accum.LessThan(&existing) {
			ranges = append(ranges, accum)
			ranges = append(ranges, m.ranges[i:]...)
			appended = true
			break
		} else if overlaps, combined := accum.Overlaps(&existing); overlaps {
			accum = *combined
		} else {
			ranges = append(ranges, existing)
		}
	}
	if !appended {
		ranges = append(ranges, accum)
	}
	m.ranges = ranges
}

func (m *MultiRange) RemoveElement(el int) {
	ranges := []intRange{}
	for i, r := range m.ranges {
		if r.Contains(el) {
			split := r.Remove(el)
			ranges = append(ranges, split...)
			ranges = append(ranges, m.ranges[i+1:]...)
			break
		} else {
			ranges = append(ranges, r)
		}
	}
	m.ranges = ranges
}
