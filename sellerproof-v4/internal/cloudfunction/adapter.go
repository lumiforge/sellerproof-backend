package cloudfunction

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"

	"github.com/lumiforge/sellerproof-backend/internal/bootstrap"
)

// CloudFunctionRequest структура запроса от API Gateway
type CloudFunctionRequest struct {
	HTTPMethod        string            `json:"httpMethod"`
	Headers           map[string]string `json:"headers"`
	Path              string            `json:"path"`
	QueryStringParams map[string]string `json:"queryStringParameters"`
	Body              string            `json:"body"`
	IsBase64Encoded   bool              `json:"isBase64Encoded"`
}

// CloudFunctionResponse структура ответа для API Gateway
type CloudFunctionResponse struct {
	StatusCode      int               `json:"statusCode"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	IsBase64Encoded bool              `json:"isBase64Encoded"`
}

var (
	apiHandler http.Handler
	initOnce   sync.Once
	initErr    error
)

// Handler - главная функция для Cloud Function (JSON trigger)
func Handler(ctx context.Context, request []byte) ([]byte, error) {
	// Ленивая инициализация через bootstrap
	initOnce.Do(func() {
		apiHandler, initErr = bootstrap.Initialize(ctx)
	})

	if initErr != nil {
		slog.Error("Failed to initialize application", "error", initErr)
		return respondError(500, "Failed to initialize: "+initErr.Error())
	}

	// Парсинг запроса от API Gateway
	var cfReq CloudFunctionRequest
	if err := json.Unmarshal(request, &cfReq); err != nil {
		slog.Error("Failed to parse request", "error", err)
		return respondError(400, "Invalid request format")
	}

	slog.Info("Processing request",
		"method", cfReq.HTTPMethod,
		"path", cfReq.Path,
	)

	// Создаём HTTP запрос из Cloud Function request
	httpReq, err := buildHTTPRequest(&cfReq)
	if err != nil {
		slog.Error("Failed to build HTTP request", "error", err)
		return respondError(400, "Failed to build request")
	}

	// Создаём ResponseRecorder для захвата ответа
	rr := httptest.NewRecorder()

	// Обрабатываем запрос через инициализированный роутер
	apiHandler.ServeHTTP(rr, httpReq)

	// Конвертируем HTTP response в Cloud Function response
	return buildCloudFunctionResponse(rr), nil
}

// buildHTTPRequest - создание HTTP запроса из Cloud Function request
func buildHTTPRequest(cfReq *CloudFunctionRequest) (*http.Request, error) {
	// Создаём body reader
	var bodyReader io.Reader
	if cfReq.Body != "" {
		bodyReader = bytes.NewBufferString(cfReq.Body)
	}

	// Создаём HTTP запрос
	req, err := http.NewRequest(cfReq.HTTPMethod, cfReq.Path, bodyReader)
	if err != nil {
		return nil, err
	}

	// Добавляем заголовки
	for key, value := range cfReq.Headers {
		req.Header.Set(key, value)
	}

	// Добавляем query parameters
	if len(cfReq.QueryStringParams) > 0 {
		q := req.URL.Query()
		for key, value := range cfReq.QueryStringParams {
			q.Add(key, value)
		}
		req.URL.RawQuery = q.Encode()
	}

	return req, nil
}

// buildCloudFunctionResponse - создание Cloud Function response из HTTP response
func buildCloudFunctionResponse(rr *httptest.ResponseRecorder) []byte {
	// Конвертируем заголовки
	headers := make(map[string]string)
	for key, values := range rr.Header() {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Создаём response
	response := CloudFunctionResponse{
		StatusCode:      rr.Code,
		Headers:         headers,
		Body:            rr.Body.String(),
		IsBase64Encoded: false,
	}

	// Сериализуем в JSON
	respData, _ := json.Marshal(response)
	return respData
}

// respondError - вспомогательная функция для ответа об ошибке
func respondError(statusCode int, message string) ([]byte, error) {
	errorBody := map[string]string{
		"error": message,
	}
	body, _ := json.Marshal(errorBody)

	response := CloudFunctionResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body:            string(body),
		IsBase64Encoded: false,
	}

	return json.Marshal(response)
}
