package main

import (
	"fmt"
	"math"
)

func credentialUID(value int) (uint32, error) {
	if value < 0 || uint64(value) > math.MaxUint32 {
		return 0, fmt.Errorf("credential UID %d exceeds uint32 bounds", value)
	}
	return uint32(value), nil
}
