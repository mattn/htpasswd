package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
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
	password.Register(password.APR1)
}

func main() {
	var create bool
	var dontupdate bool
	var usestdin bool
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
	flag.BoolVar(&usestdin, "b", false, "Use the password from the command line rather than prompting for it.")
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

	if flag.NArg() != 2 && flag.NArg() != 3 {
		flag.Usage()
		os.Exit(130)
	}
	file := flag.Arg(0)
	user := flag.Arg(1)

	var f *os.File
	var err error

	if dontupdate {
		f = os.Stdout
	} else if create {
		f, err = os.Create(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "htpasswd: cannot open file %s for read/write access\n", file)
			os.Exit(1)
		}
		defer f.Close()
	} else {
		f, err = os.Open(file)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "htpasswd: cannot modify file %s; use '-c' to create it\n", file)
			} else {
				fmt.Fprintf(os.Stderr, "htpasswd: cannot open file %s for read/write access\n", file)
			}
			os.Exit(1)
		}
		defer f.Close()
	}

	var input string
	if flag.NArg() == 2 {
		t, err := tty.Open()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print("New password: ")
		input, err = t.ReadPasswordNoEcho()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print("Re-type new password: ")
		retry, err := t.ReadPasswordNoEcho()
		if err != nil {
			log.Fatal(err)
		}
		if input != retry {
			fmt.Fprintln(os.Stderr, "htpasswd: password verification error")
			os.Exit(3)
		}
	} else {
		input = flag.Arg(2)
	}

	var result string
	if !noencrypt {
		if forcebcrypt {
			b, err := bcrypt.GenerateFromPassword([]byte(input), bcryptcost)
			if err != nil {
				log.Fatal(err)
			}
			result = string(b)
		} else {
			s, err := randomString(8)
			if err != nil {
				log.Fatal(err)
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

	found := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		token := strings.SplitN(line, ":", 2)
		if len(token) != 2 {
			continue
		}
		if token[0] == user {
			found = true
			if !deleteuser {
				f.WriteString(user + ":" + result + "\n")
			}
		} else {
			f.WriteString(line + "\n")
		}
	}
	if !found && !deleteuser {
		f.WriteString(user + ":" + result + "\n")
	}
}
