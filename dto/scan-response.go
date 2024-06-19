package dto

type ScanResponse struct {
	Issues []Issue `json:"issues"`
	Error  string  `json:"error"`
}
