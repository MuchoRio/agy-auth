package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fikrilal/agy-auth/internal/backup"
)

func (a *App) readLine(prompt string) (string, error) {
	fmt.Fprint(a.promptWriter(), prompt)
	if a.reader == nil {
		a.reader = bufio.NewReader(a.In)
	}
	line, err := a.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSpace(strings.TrimRight(line, "\r\n"))
	if line == "" && errors.Is(err, io.EOF) {
		return "", io.EOF
	}
	return line, nil
}

func (a *App) color(code, value string) string {
	if !a.OutTTY || a.NoColor || os.Getenv("NO_COLOR") != "" {
		return value
	}
	return code + value + "\x1b[0m"
}

func (a *App) green(value string) string  { return a.color("\x1b[32m", value) }
func (a *App) yellow(value string) string { return a.color("\x1b[33m", value) }
func (a *App) red(value string) string    { return a.color("\x1b[31m", value) }
func (a *App) cyan(value string) string   { return a.color("\x1b[36m", value) }
func (a *App) dim(value string) string    { return a.color("\x1b[2m", value) }
func (a *App) bold(value string) string   { return a.color("\x1b[1m", value) }

func humanUntil(target time.Time, now time.Time) string {
	if target.IsZero() {
		return "-"
	}
	delta := target.Sub(now)
	if delta <= 0 {
		return "expired"
	}
	return "in " + humanDuration(delta)
}

func formatResetTime(target, now time.Time) string {
	if target.IsZero() {
		return "-"
	}
	delta := target.Sub(now)
	if delta <= 0 {
		return "ready"
	}

	loc := now.Location()
	targetLoc := target.In(loc)
	nowLoc := now

	totalMins := int(delta.Round(time.Minute).Minutes())
	var dur string
	if totalMins < 1 {
		dur = "<1m"
	} else {
		days := totalMins / (24 * 60)
		remMins := totalMins % (24 * 60)
		hours := remMins / 60
		mins := remMins % 60
		if days > 0 && hours > 0 {
			dur = fmt.Sprintf("%dd %dh", days, hours)
		} else if days > 0 {
			dur = fmt.Sprintf("%dd", days)
		} else if hours > 0 && mins > 0 {
			dur = fmt.Sprintf("%dh %dm", hours, mins)
		} else if hours > 0 {
			dur = fmt.Sprintf("%dh", hours)
		} else {
			dur = fmt.Sprintf("%dm", mins)
		}
	}

	timeStr := targetLoc.Format("15:04")
	sameDay := targetLoc.Year() == nowLoc.Year() && targetLoc.YearDay() == nowLoc.YearDay()
	if sameDay {
		return fmt.Sprintf("%s (%s)", timeStr, dur)
	}

	targetMidnight := time.Date(targetLoc.Year(), targetLoc.Month(), targetLoc.Day(), 0, 0, 0, 0, loc)
	nowMidnight := time.Date(nowLoc.Year(), nowLoc.Month(), nowLoc.Day(), 0, 0, 0, 0, loc)
	daysDiff := int(targetMidnight.Sub(nowMidnight).Hours() / 24)

	if daysDiff >= 1 && daysDiff <= 7 {
		dayStr := targetLoc.Format("Mon")
		return fmt.Sprintf("%s %s (%s)", dayStr, timeStr, dur)
	}

	dateStr := targetLoc.Format("02 Jan")
	return fmt.Sprintf("%s %s (%s)", dateStr, timeStr, dur)
}

func humanDuration(delta time.Duration) string {
	if delta < time.Minute {
		return "<1m"
	}
	delta = delta.Round(time.Minute)
	days := int(delta / (24 * time.Hour))
	delta -= time.Duration(days) * 24 * time.Hour
	hours := int(delta / time.Hour)
	delta -= time.Duration(hours) * time.Hour
	minutes := int(delta / time.Minute)

	switch {
	case days > 0 && hours > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case days > 0:
		return fmt.Sprintf("%dd", days)
	case hours > 0 && minutes > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	case hours > 0:
		return fmt.Sprintf("%dh", hours)
	default:
		return fmt.Sprintf("%dm", minutes)
	}
}

func sanitizeFilename(value string) string {
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '.', r == '-', r == '_', r == '@':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	result := strings.Trim(builder.String(), "-.")
	if result == "" {
		result = "account"
	}
	if len(result) > 80 {
		result = result[:80]
	}
	return result
}

func shortID(id string) string {
	if len(id) <= 9 {
		return id
	}
	return id[:9]
}

func openBrowser(url string) error {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return errors.New("SSH session detected")
	}
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", url)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		command = exec.Command("xdg-open", url)
	}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Start()
}

// runningAgyCount reports the number of agy processes. It returns -1 when the
// platform does not expose an inexpensive way to check.
func runningAgyCount() int {
	switch runtime.GOOS {
	case "linux":
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return -1
		}
		count := 0
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			comm, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			if err != nil {
				continue
			}
			if strings.TrimSpace(string(comm)) == "agy" {
				count++
			}
		}
		return count
	case "windows":
		out, err := exec.Command("tasklist", "/FO", "CSV", "/NH", "/FI", "IMAGENAME eq agy.exe").Output()
		if err != nil {
			return -1
		}
		count := 0
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), `"agy.exe"`) {
				count++
			}
		}
		return count
	default:
		out, err := exec.Command("ps", "-axo", "comm=").Output()
		if err != nil {
			return -1
		}
		count := 0
		for _, line := range strings.Split(string(out), "\n") {
			base := filepath.Base(strings.TrimSpace(line))
			if base == "agy" {
				count++
			}
		}
		return count
	}
}

func (a *App) cliSettingsPath() string {
	if env := os.Getenv("AGY_CLI_SETTINGS_FILE"); env != "" {
		return env
	}
	if a != nil && a.Storage != nil && a.Storage.FilePath != "" {
		return filepath.Join(filepath.Dir(a.Storage.FilePath), "settings.json")
	}
	return ""
}

func (a *App) detectCLIModelOverride() string {
	path := a.cliSettingsPath()
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var settings struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return ""
	}
	return strings.TrimSpace(settings.Model)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	return backup.WriteFileAtomic(path, data, mode)
}
