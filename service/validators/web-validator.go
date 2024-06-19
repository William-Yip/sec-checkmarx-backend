package validators

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sec-checkmarx/dto"
	"strconv"
	"strings"
)

type WebValidator struct{}

var webCheckersMap = map[string]func(string, string) []dto.Issue{
	"XSS": checkHTMLIssues,
}

func containsWebCheck(checks []dto.SecurityChecks) bool {
	hasCheck := false
	for _, check := range checks {
		_, containsKey := webCheckersMap[string(check)]
		if containsKey {
			hasCheck = true
		}
	}
	return hasCheck
}

func (g WebValidator) Validate(path string, checks []dto.SecurityChecks) ([]dto.Issue, error) {
	issues := make([]dto.Issue, 0)

	// validate web checks
	if !containsWebCheck(checks) {
		return issues, errors.New("there wasn't any valid web checks")
	}

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if !info.IsDir() && (strings.HasSuffix(filePath, ".html") || strings.HasSuffix(filePath, ".js")) {
			content, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}
			for _, check := range checks {
				checkerFn, exists := webCheckersMap[string(check)]
				if exists {
					issuesSlice := checkerFn(filePath, string(content))
					issues = append(issues, issuesSlice...)
				}
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return issues, nil
}

func checkHTMLIssues(filePath, content string) []dto.Issue {
	var issues []dto.Issue

	// Check for <script> tags that may indicate potential XSS vulnerabilities
	scriptPattern := regexp.MustCompile(`(?i)<script.*?>.*?</script>`)
	scriptMatches := scriptPattern.FindAllStringIndex(content, -1)
	for _, match := range scriptMatches {
		line, col := getLineAndColumn(content, match[0])
		issues = append(issues, dto.Issue{
			File:    filePath,
			Details: "Potential XSS vulnerability detected in <script> tag",
			Line:    strconv.Itoa(line),
			Column:  strconv.Itoa(col),
		})
	}

	// Check for alert() function calls
	alertPattern := regexp.MustCompile(`(?i)\balert\s*\(`)
	alertMatches := alertPattern.FindAllStringIndex(content, -1)
	for _, match := range alertMatches {
		line, col := getLineAndColumn(content, match[0])
		issues = append(issues, dto.Issue{
			File:    filePath,
			Details: "XSS - Usage of alert() detected",
			Line:    strconv.Itoa(line),
			Column:  strconv.Itoa(col),
		})
	}

	return issues
}

func getLineAndColumn(content string, index int) (int, int) {
	lines := strings.Split(content[:index], "\n")
	line := len(lines)
	col := index - len(strings.Join(lines[:line-1], "\n")) + 1
	return line, col
}

func containsWebSecurityCheck(checks []dto.SecurityChecks, str string) bool {
	for _, elem := range checks {
		if string(elem) == str {
			return true
		}
	}

	return false
}
