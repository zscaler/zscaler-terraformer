/*
Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

                            MIT License
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package conversion

import (
	"time"
)

func EpochToRFC1123(epoch int64) string {
	t := time.Unix(epoch, 0).UTC()
	return t.Format(time.RFC1123)
}

/*
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
*/
