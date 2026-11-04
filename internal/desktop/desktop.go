package desktop

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fikrilal/agy-auth/internal/backup"
)

var (
	ErrNoProfile      = errors.New("no Antigravity desktop profile found")
	ErrRunningProcess = errors.New("Antigravity desktop is currently running")
	ErrBinaryNotFound = errors.New("Antigravity desktop binary not found")
)

const DesktopRetention = 5

// AuthFiles are the specific authentication and identity state files in
// the Electron user data directory that must be snapshotted and restored.
var AuthFiles = []string{
	"Cookies",
	"Cookies-journal",
	"Cookies-wal",
	"Cookies-shm",
	"app_storage.json",
	"Preferences",
}

// AuthDirs are the subdirectories in user data containing session state.
var AuthDirs = []string{
	"Local Storage",
}

// ProcessOps abstracts process detection and management for testability.
type ProcessOps struct {
	FindProcesses func() ([]int, error)
	KillProcess   func(pid int) error
	StartProcess  func(bin string) error
}

// Manager coordinates profile snapshots, restoration, and process lifecycle
// for the Antigravity Desktop application.
type Manager struct {
	ConfigDir string
	BinPath   string
	BackupDir string
	Codec     backup.Codec
	Ops       *ProcessOps
}

func (m *Manager) SetCodec(codec backup.Codec) {
	m.Codec = codec
}

// NewManager creates a desktop manager for the given configuration directory.
func NewManager(configDir string, binPath string, backupDir string) *Manager {
	if configDir == "" {
		configDir = DefaultConfigDir()
	}
	if binPath == "" {
		binPath = DefaultBinaryPath()
	}
	return &Manager{
		ConfigDir: configDir,
		BinPath:   binPath,
		BackupDir: backupDir,
	}
}

// DefaultConfigDir resolves the Antigravity Electron userData directory.
func DefaultConfigDir() string {
	if env := os.Getenv("AGY_DESKTOP_HOME"); env != "" {
		return env
	}
	if env := os.Getenv("AGY_DESKTOP_CONFIG_DIR"); env != "" {
		return env
	}
	base, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "Antigravity")
	}
	return filepath.Join(base, "Antigravity")
}

// DefaultBinaryPath resolves the installed Antigravity desktop executable.
func DefaultBinaryPath() string {
	if env := os.Getenv("AGY_DESKTOP_BIN"); env != "" {
		return env
	}
	switch runtime.GOOS {
	case "darwin":
		return "/Applications/Antigravity.app/Contents/MacOS/Antigravity"
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local = `C:\Users\Default\AppData\Local`
		}
		return filepath.Join(local, "Programs", "Antigravity", "Antigravity.exe")
	default:
		candidates := []string{
			"/opt/antigravity/Antigravity-x64/antigravity",
			"/opt/antigravity/antigravity",
			"/usr/bin/antigravity",
			"/usr/local/bin/antigravity",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
		if p, err := exec.LookPath("antigravity"); err == nil {
			return p
		}
		return candidates[0]
	}
}

// HasProfile checks if the specified directory contains an active session.
func HasProfile(dir string) bool {
	if _, err := os.Stat(dir); err != nil {
		return false
	}
	for _, f := range AuthFiles {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	for _, d := range AuthDirs {
		if _, err := os.Stat(filepath.Join(dir, d)); err == nil {
			return true
		}
	}
	return false
}

// DetectAccountEmail inspects app_storage.json in ConfigDir and returns the
// logged-in account email when present, or an empty string if unknown.
func (m *Manager) DetectAccountEmail() string {
	if m == nil || m.ConfigDir == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(m.ConfigDir, "app_storage.json"))
	if err != nil {
		return ""
	}
	if m.Codec != nil && m.Codec.IsEncrypted(raw) {
		if decoded, decErr := m.Codec.Decode(raw); decErr == nil {
			raw = decoded
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ""
	}
	return extractEmailFromMap(doc)
}

func extractEmailFromMap(doc map[string]any) string {
	for _, key := range []string{"email", "userEmail", "accountEmail", "lastLoginUsername", "username", "user", "account"} {
		val, ok := doc[key]
		if !ok {
			continue
		}
		switch v := val.(type) {
		case string:
			trimmed := strings.TrimSpace(v)
			if strings.Contains(trimmed, "@") {
				return trimmed
			}
		case map[string]any:
			if nested := extractEmailFromMap(v); nested != "" {
				return nested
			}
		}
	}
	return ""
}

func (m *Manager) encodeData(raw []byte) ([]byte, error) {
	if m == nil || m.Codec == nil {
		return raw, nil
	}
	return m.Codec.Encode(raw)
}

func (m *Manager) decodeData(raw []byte) ([]byte, error) {
	if m == nil || m.Codec == nil {
		return raw, nil
	}
	return m.Codec.Decode(raw)
}

// Snapshot copies the whitelisted session files from ConfigDir into destDir atomically.
func (m *Manager) Snapshot(destDir string) error {
	if !HasProfile(m.ConfigDir) {
		return ErrNoProfile
	}
	parentDir := filepath.Dir(destDir)
	if err := os.MkdirAll(parentDir, 0o700); err != nil {
		return fmt.Errorf("create snapshot parent directory: %w", err)
	}
	if err := os.Chmod(parentDir, 0o700); err != nil {
		return err
	}

	stageDir, err := os.MkdirTemp(parentDir, "."+filepath.Base(destDir)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create snapshot staging directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(stageDir)
	}()
	if err := os.Chmod(stageDir, 0o700); err != nil {
		return err
	}

	for _, file := range AuthFiles {
		srcPath := filepath.Join(m.ConfigDir, file)
		if _, err := os.Stat(srcPath); err != nil {
			continue
		}
		data, err := os.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", file, err)
		}
		encoded, err := m.encodeData(data)
		if err != nil {
			return fmt.Errorf("encrypt %s snapshot: %w", file, err)
		}
		destPath := filepath.Join(stageDir, file)
		if err := writeFileAtomic(destPath, encoded, 0o600); err != nil {
			return fmt.Errorf("write %s snapshot: %w", file, err)
		}
	}

	for _, dir := range AuthDirs {
		srcSub := filepath.Join(m.ConfigDir, dir)
		if _, err := os.Stat(srcSub); err != nil {
			continue
		}
		destSub := filepath.Join(stageDir, dir)
		if err := copyDirTransform(srcSub, destSub, m.encodeData); err != nil {
			return fmt.Errorf("copy %s: %w", dir, err)
		}
	}

	return swapDirAtomic(stageDir, destDir)
}

// Restore restores the session profile from srcDir into ConfigDir atomically, backing up the current profile first.
func (m *Manager) Restore(srcDir string) error {
	if !HasProfile(srcDir) {
		return fmt.Errorf("source %s: %w", srcDir, ErrNoProfile)
	}

	if err := os.MkdirAll(m.ConfigDir, 0o700); err != nil {
		return fmt.Errorf("ensure config dir: %w", err)
	}
	if err := os.Chmod(m.ConfigDir, 0o700); err != nil {
		return err
	}

	stageRoot, err := os.MkdirTemp(m.ConfigDir, ".restore-stage-*")
	if err != nil {
		return fmt.Errorf("create restore staging dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(stageRoot)
	}()
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		return err
	}

	stagedFiles := make(map[string][]byte, len(AuthFiles))
	for _, file := range AuthFiles {
		srcPath := filepath.Join(srcDir, file)
		if _, err := os.Stat(srcPath); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("stat %s: %w", file, err)
		}
		raw, err := os.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", file, err)
		}
		decoded, err := m.decodeData(raw)
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", file, err)
		}
		stagedFiles[file] = decoded
	}

	stagedDirs := make(map[string]string, len(AuthDirs))
	for _, dir := range AuthDirs {
		srcSub := filepath.Join(srcDir, dir)
		if _, err := os.Stat(srcSub); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("stat %s: %w", dir, err)
		}
		stageSub := filepath.Join(stageRoot, dir)
		if err := copyDirTransform(srcSub, stageSub, m.decodeData); err != nil {
			return fmt.Errorf("stage %s: %w", dir, err)
		}
		stagedDirs[dir] = stageSub
	}

	if m.BackupDir != "" && HasProfile(m.ConfigDir) {
		if err := m.backupLive(); err != nil {
			return fmt.Errorf("desktop profile backup: %w", err)
		}
	}

	for _, file := range AuthFiles {
		destPath := filepath.Join(m.ConfigDir, file)
		data, ok := stagedFiles[file]
		if !ok {
			_ = os.Remove(destPath)
			continue
		}
		if err := writeFileAtomic(destPath, data, 0o600); err != nil {
			return fmt.Errorf("restore %s: %w", file, err)
		}
	}

	for _, dir := range AuthDirs {
		destSub := filepath.Join(m.ConfigDir, dir)
		stageSub, ok := stagedDirs[dir]
		if !ok {
			_ = os.RemoveAll(destSub)
			continue
		}
		if err := swapDirAtomic(stageSub, destSub); err != nil {
			return fmt.Errorf("restore %s: %w", dir, err)
		}
	}
	return nil
}

func (m *Manager) backupLive() error {
	backupBase := filepath.Join(m.BackupDir, "desktop")
	if err := os.MkdirAll(backupBase, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(backupBase, 0o700); err != nil {
		return err
	}

	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	target := filepath.Join(backupBase, fmt.Sprintf("desktop-%s", stamp))
	for i := 1; ; i++ {
		if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
			break
		}
		target = filepath.Join(backupBase, fmt.Sprintf("desktop-%s-%d", stamp, i))
	}

	if err := m.Snapshot(target); err != nil {
		return err
	}
	m.pruneBackups(backupBase, DesktopRetention)
	return nil
}

func (m *Manager) pruneBackups(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var backups []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "desktop-") {
			backups = append(backups, filepath.Join(dir, e.Name()))
		}
	}
	if len(backups) <= keep {
		return
	}
	sort.Strings(backups)
	for i := 0; i < len(backups)-keep; i++ {
		_ = os.RemoveAll(backups[i])
	}
}

// IsRunning reports whether Antigravity Desktop is currently running and returns its main PID.
func (m *Manager) IsRunning() (bool, int, error) {
	if m.Ops != nil && m.Ops.FindProcesses != nil {
		pids, err := m.Ops.FindProcesses()
		if err != nil {
			return false, 0, err
		}
		if len(pids) > 0 {
			return true, pids[0], nil
		}
		return false, 0, nil
	}
	return findDefaultProcesses(m.BinPath)
}

// Terminate sends a graceful termination signal and awaits exit, falling back to force kill.
func (m *Manager) Terminate(pid int, timeout time.Duration) error {
	if m.Ops != nil && m.Ops.KillProcess != nil {
		return m.Ops.KillProcess(pid)
	}
	if pid <= 0 || pid == os.Getpid() {
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}

	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/PID", strconv.Itoa(pid)).Run()
	} else {
		_ = proc.Signal(syscall.SIGTERM)
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !isProcessAlive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	_ = proc.Kill()
	time.Sleep(100 * time.Millisecond)
	return nil
}

// Relaunch launches the Antigravity Desktop binary detached from the current process.
func (m *Manager) Relaunch() error {
	bin := m.BinPath
	if bin == "" {
		bin = DefaultBinaryPath()
	}
	if m.Ops != nil && m.Ops.StartProcess != nil {
		return m.Ops.StartProcess(bin)
	}
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("%w: %s", ErrBinaryNotFound, bin)
	}
	cmd := exec.Command(bin)
	cmd.SysProcAttr = detachSysProcAttr()
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}

func findDefaultProcesses(configuredBin string) (bool, int, error) {
	selfPID := os.Getpid()
	if runtime.GOOS == "linux" {
		entries, err := os.ReadDir("/proc")
		if err == nil {
			var mainPID int
			found := false
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				pid, err := strconv.Atoi(e.Name())
				if err != nil || pid <= 0 || pid == selfPID {
					continue
				}
				commPath := filepath.Join("/proc", e.Name(), "comm")
				commBytes, err := os.ReadFile(commPath)
				if err != nil {
					continue
				}
				comm := strings.TrimSpace(string(commBytes))
				if strings.EqualFold(comm, "antigravity") {
					cmdPath := filepath.Join("/proc", e.Name(), "cmdline")
					cmdBytes, err := os.ReadFile(cmdPath)
					if err == nil && bytes.Contains(cmdBytes, []byte("--type=")) {
						continue
					}
					found = true
					mainPID = pid
					break
				}
			}
			if found {
				return true, mainPID, nil
			}
			return false, 0, nil
		}
	}

	if runtime.GOOS == "windows" {
		out, err := exec.Command("tasklist", "/FO", "CSV", "/NH", "/FI", "IMAGENAME eq Antigravity.exe").Output()
		if err != nil {
			return false, 0, nil
		}
		if pid, ok := parseWindowsTasklist(string(out), selfPID); ok {
			return true, pid, nil
		}
		return false, 0, nil
	}

	out, err := exec.Command("ps", "-axo", "pid=,args=").Output()
	if err != nil {
		return false, 0, nil
	}
	if pid, ok := parsePSOutput(string(out), selfPID, configuredBin); ok {
		return true, pid, nil
	}
	return false, 0, nil
}

func parseWindowsTasklist(output string, selfPID int) (int, bool) {
	reader := csv.NewReader(strings.NewReader(output))
	records, err := reader.ReadAll()
	if err != nil {
		return 0, false
	}
	for _, record := range records {
		if len(record) < 2 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record[0]), "Antigravity.exe") {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(record[1]))
		if err == nil && pid > 0 && pid != selfPID {
			return pid, true
		}
	}
	return 0, false
}

func parsePSOutput(output string, selfPID int, configuredBin string) (int, bool) {
	for _, line := range strings.Split(output, "\n") {
		if pid, ok := matchDesktopProcessLine(line, selfPID, configuredBin); ok {
			return pid, true
		}
	}
	return 0, false
}

func matchDesktopProcessLine(line string, selfPID int, configuredBin string) (int, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return 0, false
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return 0, false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 || pid == selfPID {
		return 0, false
	}
	args := strings.TrimSpace(trimmed[len(fields[0]):])
	if strings.Contains(args, "--type=") {
		return 0, false
	}

	exePart := args
	if idx := strings.Index(exePart, " -"); idx >= 0 {
		exePart = strings.TrimSpace(exePart[:idx])
	}
	if configuredBin != "" && configuredBin != "/bin/echo" {
		if exePart == configuredBin || strings.HasPrefix(args, configuredBin+" ") {
			return pid, true
		}
	}
	const macAppSuffix = "Antigravity.app/Contents/MacOS/Antigravity"
	if strings.HasSuffix(exePart, macAppSuffix) || strings.Contains(exePart, macAppSuffix+" ") {
		return pid, true
	}

	firstToken := fields[1]
	base := strings.ToLower(filepath.Base(firstToken))
	if base == "antigravity" || base == "antigravity.exe" {
		return pid, true
	}
	return 0, false
}

func swapDirAtomic(stageDir, destDir string) error {
	if _, err := os.Stat(destDir); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(stageDir, destDir); err != nil {
			return err
		}
		return os.Chmod(destDir, 0o700)
	} else if err != nil {
		return err
	}

	backupDir := fmt.Sprintf("%s.old-%d", destDir, time.Now().UnixNano())
	if err := os.Rename(destDir, backupDir); err != nil {
		return err
	}
	if err := os.Rename(stageDir, destDir); err != nil {
		_ = os.Rename(backupDir, destDir)
		return err
	}
	_ = os.RemoveAll(backupDir)
	return os.Chmod(destDir, 0o700)
}

func copyDirTransform(src, dest string, transform func([]byte) ([]byte, error)) error {
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dest, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		destPath := filepath.Join(dest, entry.Name())
		if entry.IsDir() {
			if err := copyDirTransform(srcPath, destPath, transform); err != nil {
				return err
			}
		} else {
			data, err := os.ReadFile(srcPath)
			if err != nil {
				return err
			}
			if transform != nil {
				data, err = transform(data)
				if err != nil {
					return err
				}
			}
			if err := writeFileAtomic(destPath, data, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return os.Chmod(path, mode)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".desktop-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
