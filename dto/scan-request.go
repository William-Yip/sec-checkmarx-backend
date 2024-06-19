package dto

import (
	"errors"
	"os"
)

type ScanRequest struct {
	Path     string           `json:"path"`
	CodeType string           `json:"codeType"`
	Checks   []SecurityChecks `json:"checks`
}

func (s ScanRequest) ValidateDTO() error {
	path := s.Path
	if len(path) == 0 {
		return errors.New("provide a valid folder path")
	}
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return errors.New("folder does not exists")
	}

	codeType := s.CodeType
	if len(codeType) == 0 {
		return errors.New("provide a valid code type")
	}
	checks := s.Checks

	if len(checks) == 0 {
		return errors.New("provide at least one security check")
	}
	return nil
}

type SecurityChecks string

// Declare constants of type Status
const (
	SQLI   SecurityChecks = "SQLI"
	XSS    SecurityChecks = "XSS"
	CRYPTO SecurityChecks = "CRYPTO"
)

type Issue struct {
	File    string `json:"file"`
	Details string `json:"details"`
	Line    string `json:"line"`
	Column  string `json:"column"`
}
