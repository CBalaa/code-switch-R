package main

import (
	"bufio"
	"codeswitch/services"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("missing command")
	}

	store := services.NewUserStore()
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("add", flag.ExitOnError)
		username := fs.String("username", "", "username")
		_ = fs.Parse(args[1:])
		password, err := promptNewPassword()
		if err != nil {
			return err
		}
		user, err := store.AddUser(*username, password)
		if err != nil {
			return err
		}
		fmt.Printf("created user %s (%s)\n", user.Username, user.ID)
	case "list":
		users, err := store.ListUsers()
		if err != nil {
			return err
		}
		if len(users) == 0 {
			fmt.Printf("no users found (%s)\n", store.Path())
			return nil
		}
		fmt.Printf("%-28s %-24s %-8s %s\n", "ID", "USERNAME", "ENABLED", "CREATED_AT")
		for _, user := range users {
			fmt.Printf("%-28s %-24s %-8t %s\n", user.ID, user.Username, user.Enabled, user.CreatedAt.Format("2006-01-02T15:04:05Z"))
		}
	case "disable", "enable":
		fs := flag.NewFlagSet(args[0], flag.ExitOnError)
		username := fs.String("username", "", "username")
		_ = fs.Parse(args[1:])
		if err := store.SetUserEnabled(*username, args[0] == "enable"); err != nil {
			return err
		}
		fmt.Printf("%sd user %s\n", args[0], strings.TrimSpace(*username))
	case "reset-password":
		fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
		username := fs.String("username", "", "username")
		_ = fs.Parse(args[1:])
		password, err := promptNewPassword()
		if err != nil {
			return err
		}
		if err := store.ResetPassword(*username, password); err != nil {
			return err
		}
		fmt.Printf("password reset for %s\n", strings.TrimSpace(*username))
	default:
		usage()
		return fmt.Errorf("unknown command: %s", args[0])
	}
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  scripts/manage-users add --username <name>
  scripts/manage-users list
  scripts/manage-users disable --username <name>
  scripts/manage-users enable --username <name>
  scripts/manage-users reset-password --username <name>`)
}

func promptNewPassword() (string, error) {
	password, err := readPassword("Password: ")
	if err != nil {
		return "", err
	}
	confirm, err := readPassword("Confirm password: ")
	if err != nil {
		return "", err
	}
	if password != confirm {
		return "", errors.New("passwords do not match")
	}
	if err := services.ValidateUserPassword(password); err != nil {
		return "", err
	}
	return password, nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if isTerminal(os.Stdin.Fd()) {
		_ = exec.Command("stty", "-echo").Run()
		defer func() {
			_ = exec.Command("stty", "echo").Run()
			fmt.Fprintln(os.Stderr)
		}()
	}
	reader := bufio.NewReader(os.Stdin)
	value, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(value, "\r\n"), nil
}

func isTerminal(fd uintptr) bool {
	var stat syscall.Stat_t
	return syscall.Fstat(int(fd), &stat) == nil && (stat.Mode&syscall.S_IFMT) == syscall.S_IFCHR
}
