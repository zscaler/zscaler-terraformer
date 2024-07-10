// Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

//                             MIT License
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"io"
	"log"
	"os"
	"strings"

	"github.com/zscaler/zscaler-terraformer/cmd"
)

// TerraformerWriter is a custom writer to filter log messages.
type TerraformerWriter struct {
	io.Writer
}

// Write filters out [TRACE] and [DEBUG] log messages.
func (t TerraformerWriter) Write(p []byte) (n int, err error) {
	if !strings.Contains(string(p), "[TRACE]") && !strings.Contains(string(p), "[DEBUG]") {
		return os.Stdout.Write(p)
	}
	return len(p), nil
}

func main() {
	// Set the custom writer for log output
	log.SetOutput(TerraformerWriter{})

	// Ensure the environment variable is set to disable caching
	os.Setenv("ZSCALER_SDK_CACHE_DISABLED", "true")

	// Execute the command with error handling
	if err := cmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
