package service

import (
	"errors"
	"sec-checkmarx/dto"
	"sec-checkmarx/service/validators"
)

type SecurityValidator interface {
	Validate(path string, checks []dto.SecurityChecks) ([]dto.Issue, error)
}

var securityValidatorsMap map[string]SecurityValidator = map[string]SecurityValidator{
	"golang": validators.GoValidator{},
	"web":    validators.WebValidator{},
}

func PerformScan(codeType string, path string, checks []dto.SecurityChecks) ([]dto.Issue, error) {
	issues := make([]dto.Issue, 0)

	securityValidator, exists := securityValidatorsMap[codeType]

	if !exists {
		return issues, errors.New("unsupported codeType")
	}

	i, err := securityValidator.Validate(path, checks)
	if err != nil {
		return nil, err
	}

	issues = append(issues, i...)

	return issues, nil
}
