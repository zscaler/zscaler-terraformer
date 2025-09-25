package flags

import (
	"strings"
	"testing"
	"time"
)

// Mock progress tracker for testing.
type MockProgressTracker struct {
	current     int
	total       int
	startTime   time.Time
	currentTask string
	width       int
}

func NewMockProgressTracker(total int) *MockProgressTracker {
	return &MockProgressTracker{
		current:   0,
		total:     total,
		startTime: time.Now(),
		width:     50,
	}
}

func (pt *MockProgressTracker) Update(taskName string) {
	pt.current++
	pt.currentTask = taskName
}

func TestProgressCalculations(t *testing.T) {
	// Test progress percentage calculations
	testCases := []struct {
		name               string
		total              int
		current            int
		expectedPercentage float64
		description        string
	}{
		{
			name:               "Quarter progress",
			total:              4,
			current:            1,
			expectedPercentage: 25.0,
			description:        "Should calculate 25% for 1/4",
		},
		{
			name:               "Half progress",
			total:              10,
			current:            5,
			expectedPercentage: 50.0,
			description:        "Should calculate 50% for 5/10",
		},
		{
			name:               "Complete progress",
			total:              3,
			current:            3,
			expectedPercentage: 100.0,
			description:        "Should calculate 100% for 3/3",
		},
		{
			name:               "Zero progress",
			total:              5,
			current:            0,
			expectedPercentage: 0.0,
			description:        "Should calculate 0% for 0/5",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			percentage := float64(tc.current) / float64(tc.total) * 100
			if percentage != tc.expectedPercentage {
				t.Errorf("%s: Expected %.1f%%, got %.1f%%", tc.description, tc.expectedPercentage, percentage)
			}
		})
	}
}

func TestETACalculation(t *testing.T) {
	// Test ETA calculation logic
	mockTracker := NewMockProgressTracker(10)

	// Simulate some progress
	startTime := time.Now().Add(-30 * time.Second) // 30 seconds ago
	mockTracker.startTime = startTime
	mockTracker.current = 3 // 3 out of 10 completed

	// Calculate ETA
	elapsed := time.Since(mockTracker.startTime)
	if mockTracker.current > 0 {
		totalEstimate := elapsed * time.Duration(mockTracker.total) / time.Duration(mockTracker.current)
		remaining := totalEstimate - elapsed

		// With 3/10 done in 30s, total estimate should be 100s, remaining ~70s
		expectedRemaining := 70 * time.Second
		tolerance := 5 * time.Second

		if remaining < expectedRemaining-tolerance || remaining > expectedRemaining+tolerance {
			t.Errorf("ETA calculation incorrect: expected ~%v, got %v", expectedRemaining, remaining)
		}
	}
}

func TestProgressBarFormatting(t *testing.T) {
	// Test progress bar visual formatting
	width := 20
	testCases := []struct {
		name              string
		total             int
		current           int
		expectedCompleted int
		description       string
	}{
		{
			name:              "Quarter progress bar",
			total:             4,
			current:           1,
			expectedCompleted: 5, // 25% of 20 = 5
			description:       "Should show 5 completed blocks for 25%",
		},
		{
			name:              "Half progress bar",
			total:             2,
			current:           1,
			expectedCompleted: 10, // 50% of 20 = 10
			description:       "Should show 10 completed blocks for 50%",
		},
		{
			name:              "Full progress bar",
			total:             1,
			current:           1,
			expectedCompleted: 20, // 100% of 20 = 20
			description:       "Should show 20 completed blocks for 100%",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			completed := int(float64(width) * float64(tc.current) / float64(tc.total))
			if completed != tc.expectedCompleted {
				t.Errorf("%s: Expected %d completed blocks, got %d", tc.description, tc.expectedCompleted, completed)
			}
		})
	}
}

func TestTaskNameTruncation(t *testing.T) {
	// Test task name truncation for display
	testCases := []struct {
		name        string
		taskName    string
		maxLength   int
		expectedLen int
		shouldTrunc bool
		description string
	}{
		{
			name:        "Short task name",
			taskName:    "Importing zpa_app",
			maxLength:   30,
			expectedLen: 16,
			shouldTrunc: false,
			description: "Short names should not be truncated",
		},
		{
			name:        "Long task name",
			taskName:    "Importing zpa_cloud_browser_isolation_external_profile",
			maxLength:   30,
			expectedLen: 30,
			shouldTrunc: true,
			description: "Long names should be truncated to max length",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := truncateTaskName(tc.taskName, tc.maxLength)

			if tc.shouldTrunc {
				if len(result) != tc.maxLength {
					t.Errorf("%s: Expected truncated length %d, got %d", tc.description, tc.maxLength, len(result))
				}
				if !strings.HasSuffix(result, "...") {
					t.Error("Truncated task name should end with '...'")
				}
			} else {
				if result != tc.taskName {
					t.Errorf("%s: Short task name should not be modified", tc.description)
				}
			}
		})
	}
}

// Helper function for testing task name truncation.
func truncateTaskName(taskName string, maxLength int) string {
	if len(taskName) > maxLength {
		return taskName[:maxLength-3] + "..."
	}
	return taskName
}
