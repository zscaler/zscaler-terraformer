package conversion

import (
	"fmt"
	"strconv"
	"time"
)

func EpochToRFC1123(epoch int64) string {
	t := time.Unix(epoch, 0).UTC()
	return t.Format(time.RFC1123)
}

// Converts an epoch time (in seconds, represented as a string) to a human-readable format with the specified timezone.
func EpochToRFC1123WithTimezone(epochStr string, timezone string) (string, error) {
	epoch, err := strconv.ParseInt(epochStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("failed to parse epoch time: %s", err)
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return "", fmt.Errorf("failed to load location: %s", err)
	}

	t := time.Unix(epoch, 0).In(loc)
	return t.Format(time.RFC1123), nil
}
