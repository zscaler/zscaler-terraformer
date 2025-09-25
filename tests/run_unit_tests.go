package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	fmt.Println("🧪 Running Zscaler Terraformer Unit Tests")
	fmt.Println("==========================================")

	// Get the project root directory
	projectRoot, err := findProjectRoot()
	if err != nil {
		fmt.Printf("❌ Error finding project root: %v\n", err)
		os.Exit(1)
	}

	// Change to project root
	err = os.Chdir(projectRoot)
	if err != nil {
		fmt.Printf("❌ Error changing to project root: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("📁 Project root: %s\n", projectRoot)
	fmt.Printf("🎯 Running unit tests...\n\n")

	// Run tests with verbose output
	cmd := exec.Command("go", "test", "-v", "./tests/unit/...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		fmt.Printf("\n❌ Tests failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✅ All unit tests passed!\n")

	// Run test coverage
	fmt.Printf("\n📊 Generating test coverage...\n")
	coverageCmd := exec.Command("go", "test", "-cover", "./tests/unit/...")
	coverageCmd.Stdout = os.Stdout
	coverageCmd.Stderr = os.Stderr

	err = coverageCmd.Run()
	if err != nil {
		fmt.Printf("⚠️  Coverage generation failed: %v\n", err)
	}

	fmt.Printf("\n🎉 Unit test run completed!\n")
}

func findProjectRoot() (string, error) {
	// Start from current directory and walk up to find go.mod
	currentDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := currentDir
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root directory
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("go.mod not found in %s or any parent directory", currentDir)
}
