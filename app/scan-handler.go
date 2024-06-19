package app

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sec-checkmarx/dto"
	"sec-checkmarx/service"
)

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Println("only POST method is allowed")
		writeScanErrorResponse(w, errors.New("only POST method is allowed"), http.StatusBadRequest)
		return
	}

	var scanRequest dto.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&scanRequest); err != nil {
		log.Println(err.Error())
		writeScanErrorResponse(w, err, http.StatusBadRequest)
		return
	}

	if err := scanRequest.ValidateDTO(); err != nil {
		log.Println(err.Error())
		writeScanErrorResponse(w, err, http.StatusBadRequest)
		return
	}

	issues, err := service.PerformScan(scanRequest.CodeType, scanRequest.Path, scanRequest.Checks)
	if err != nil {
		log.Println(err.Error())
		writeScanErrorResponse(w, err, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(dto.ScanResponse{Issues: issues})
}

func writeScanErrorResponse(w http.ResponseWriter, err error, httpStatus int) {
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(dto.ScanResponse{Error: err.Error()})
}
