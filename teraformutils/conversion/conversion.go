package conversion

import "time"

func EpochToRFC1123(epoch int64) string {
	t := time.Unix(epoch, 0).UTC()
	return t.Format(time.RFC1123)
}
