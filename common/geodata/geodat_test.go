package geodata

import (
	"sync"
	"testing"
)

func BenchmarkLoadIP(b *testing.B) {
	codes := []string{
		"CN",
		"US",
		"JP",
		"CA",
		"GB",
	}
	for b.Loop() {
		var wg sync.WaitGroup
		for _, code := range codes {
			wg.Go(func() {
				_, err := loadIP("geoip.dat", code)
				if err != nil {
					b.Error(err)
				}
			})
		}
		wg.Wait()
	}
}
