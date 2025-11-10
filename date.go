package ncmec

import (
	"fmt"
	"time"
)

type Date struct {
	year  int
	month time.Month
	day   int
}

func (d *Date) String() string {
	return fmt.Sprintf("%04d-%02d-%02d", d.year, d.month, d.day)
}

func (d *Date) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

func NewDate(year int, month time.Month, day int) *Date {
	return &Date{
		year:  year,
		month: month,
		day:   day,
	}
}

func FromTime(t time.Time) *Date {
	var d Date
	d.year, d.month, d.day = t.Date()
	return &d
}
