package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/mattn/go-tty"
	"github.com/nathanaelle/password"
)

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	r, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b[:r], nil
}

func randomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	for i, c := range b {
		b[i] = letters[c%byte(len(letters))]
	}
	return string(b), nil
}

func init() {
	password.Register(password.APR1, password.BCRYPT)
}

func main() {
	var create bool
	var dontupdate bool
	var useargument bool
	var noverify bool
	var forcemd5 bool
	var forcebcrypt bool
	var bcryptcost int
	var noencrypt bool
	var deleteuser bool
	var verifyuser bool
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage:
        htpasswd [-cimBdpsDv] [-C cost] passwordfile username
        htpasswd -b[cmBdpsDv] [-C cost] passwordfile username password

        htpasswd -n[imBdps] [-C cost] username
        htpasswd -nb[mBdps] [-C cost] username password
 -c  Create a new file.
 -n  Don't update file; display results on stdout.
 -b  Use the password from the command line rather than prompting for it.
 -i  Read password from stdin without verification (for script usage).
 -m  Force MD5 encryption of the password (default).
 -B  Force bcrypt encryption of the password (very secure).
 -C  Set the computing time used for the bcrypt algorithm
     (higher is more secure but slower, default: 5, valid: 4 to 31).
 -d  Force CRYPT encryption of the password (8 chars max, insecure).
 -s  Force SHA encryption of the password (insecure).
 -p  Do not encrypt the password (plaintext, insecure).
 -D  Delete the specified user.
 -v  Verify password for the specified user.
On other systems than Windows and NetWare the '-p' flag will probably not work.
The SHA algorithm does not use a salt and is less secure than the MD5 algorithm.
`)
	}
	flag.BoolVar(&create, "c", false, "Create a new file.")
	flag.BoolVar(&dontupdate, "n", false, "Don't update file; display results on stdout.")
	flag.BoolVar(&useargument, "b", false, "Use the password from the command line rather than prompting for it.")
	flag.BoolVar(&noverify, "i", false, "Read password from stdin without verification (for script usage).")
	flag.BoolVar(&forcemd5, "m", true, "Force MD5 encryption of the password (default).")
	flag.BoolVar(&forcebcrypt, "B", false, "Force bcrypt encryption of the password (very secure).")
	flag.IntVar(&bcryptcost, "C", bcrypt.DefaultCost, "Set the computing time used for the bcrypt algorithm\n(higher is more secure but slower, default: 5, valid: 4 to 31).")
	flag.BoolVar(&noencrypt, "p", false, "Do not encrypt the password (plaintext, insecure).")
	flag.BoolVar(&deleteuser, "D", false, "Delete the specified user.")
	flag.BoolVar(&verifyuser, "v", false, "Verify password for the specified user.")
	flag.Parse()

	check := 0
	if create {
		check++
	}
	if dontupdate {
		check++
	}
	if verifyuser {
		check++
	}
	if deleteuser {
		check++
	}
	if check != 0 && check > 1 {
		fmt.Fprintln(os.Stderr, "htpasswd: only one of -c -n -v -D may be specified")
		os.Exit(2)
	}

	if flag.NArg() != 2 && (!useargument || flag.NArg() != 3) {
		flag.Usage()
		os.Exit(130)
	}
	file := flag.Arg(0)
	user := flag.Arg(1)

	var content []byte
	var err error

	if dontupdate {
		content, err = ioutil.ReadAll(os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "htpasswd: %v", err)
			os.Exit(1)
		}
	} else if !create {
		f, err := os.Open(file)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "htpasswd: cannot modify file %s; use '-c' to create it\n", file)
			} else {
				fmt.Fprintf(os.Stderr, "htpasswd: cannot open file %s for read/write access\n", file)
			}
			os.Exit(1)
		}

		content, err = ioutil.ReadAll(f)
		f.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "htpasswd: %v", err)
			os.Exit(1)
		}
	}

	var input string
	if flag.NArg() == 2 && !deleteuser {
		t, err := tty.Open()
		if err != nil {
			fmt.Fprintf(os.Stderr, "htpasswd: %v", err)
			os.Exit(1)
		}
		fmt.Print("New password: ")
		input, err = t.ReadPasswordNoEcho()
		if err != nil {
			fmt.Fprintf(os.Stderr, "htpasswd: %v", err)
			os.Exit(1)
		}
		fmt.Print("Re-type new password: ")
		retry, err := t.ReadPasswordNoEcho()
		if err != nil {
			fmt.Fprintf(os.Stderr, "htpasswd: %v", err)
			os.Exit(1)
		}
		if input != retry {
			fmt.Fprintln(os.Stderr, "htpasswd: password verification error")
			os.Exit(3)
		}
	} else {
		input = flag.Arg(2)
	}

	var result string
	if !noencrypt && !deleteuser {
		if forcebcrypt {
			//password.BCRYPT.Crypt
			b, err := bcrypt.GenerateFromPassword([]byte(input), bcryptcost)
			if err != nil {
				fmt.Fprintf(os.Stderr, "htpasswd: %v", err)
				os.Exit(1)
			}
			result = string(b)
		} else {
			s, err := randomString(8)
			if err != nil {
				fmt.Fprintf(os.Stderr, "htpasswd: %v", err)
				os.Exit(1)
			}
			result = password.APR1.Crypt([]byte(input), []byte(s), nil)
		}
		if dontupdate {
			fmt.Print(result)
			return
		}
	} else {
		result = input
	}

	if create {
		err = ioutil.WriteFile(file, []byte(user+":"+result+"\n"), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "htpasswd: cannot open file %s for read/write access\n", file)
			os.Exit(1)

		}
		fmt.Fprintf(os.Stderr, "Adding password for user %s\n", user)
	} else {
		found := false
		scanner := bufio.NewScanner(bytes.NewReader(content))
		var buf bytes.Buffer
		for scanner.Scan() {
			line := scanner.Text()
			token := strings.SplitN(line, ":", 2)
			if len(token) != 2 {
				continue
			}
			if token[0] == user {
				found = true
				if !deleteuser {
					buf.WriteString(user + ":" + result + "\n")
				}
			} else {
				buf.WriteString(line + "\n")
			}
		}
		if !found && !deleteuser {
			buf.WriteString(user + ":" + result + "\n")
		}
		err = ioutil.WriteFile(file, buf.Bytes(), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "htpasswd: cannot open file %s for read/write access\n", file)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Updating password for user %s\n", user)
	}
}
