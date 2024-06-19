package validators

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sec-checkmarx/dto"
	"strings"
)

type GoValidator struct{}

// G501: Import blocklist: crypto/md5
// G502: Import blocklist: crypto/des
// G503: Import blocklist: crypto/rc4
// G504: Import blocklist: net/http/cgi
// G505: Import blocklist: crypto/sha1

// G201: SQL query construction using format string
// G202: SQL query construction using string concatenation
var goCheckersMap = map[string]string{
	"SQLI":   "G201,202,",
	"CRYPTO": "G501,G502,G503,G504,G505,",
}

func buildRules(checks []dto.SecurityChecks) (string, error) {
	templateStr := "-include="
	hasGoRule := false
	for _, check := range checks {
		checkVal, containsKey := goCheckersMap[string(check)]
		if containsKey {
			hasGoRule = true
			templateStr += checkVal
		}
	}
	if !hasGoRule {
		return "", errors.New("there wasn't any valid golang checks")
	}
	return templateStr, nil
}

func (g GoValidator) Validate(path string, checks []dto.SecurityChecks) ([]dto.Issue, error) {
	// validate checks
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, err
	}
	if strings.HasSuffix(absPath, "/") {
		absPath = absPath + "..."
	} else {
		absPath = absPath + "/..."
	}
	// add checks here
	rulesArg, err := buildRules(checks)
	if err != nil {
		return []dto.Issue{}, err
	}
	cmd := exec.Command("gosec", "-quiet", "-no-fail", "-fmt", "json", rulesArg, absPath)
	output, err := cmd.CombinedOutput()
	if err != nil && err.Error() != "exit status 1" {
		log.Println(fmt.Sprint(err))
		return nil, err
	}
	// Parse the gosec output
	var gosecOutput struct {
		Issues []dto.Issue `json:"Issues"`
	}

	res := string(output) // "" empty res means no issues found
	// log.Println(res)

	if res == "" {
		return []dto.Issue{}, nil
	}

	if err := json.Unmarshal(output, &gosecOutput); err != nil {
		log.Println(err.Error())
		return nil, err
	}

	return gosecOutput.Issues, nil
}
