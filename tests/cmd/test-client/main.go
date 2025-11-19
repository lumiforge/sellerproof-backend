package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// URL вашего сервиса в Yandex Cloud (будет установлен при сборке из Makefile)
var serviceURL string
var testTimeout = 30 // секунд по умолчанию
var testMode = ""    // "auth" или "video" или "" (все тесты)

// TestClient представляет тестовый клиент для REST API
type TestClient struct {
	baseURL    string
	httpClient *http.Client
	token      string
	userID     string
}

// NewTestClient создает новый тестовый клиент
func NewTestClient() (*TestClient, error) {
	// Нормализуем URL
	normalizedURL := normalizeURL(serviceURL)

	// Создаем HTTP клиент
	client := &TestClient{
		baseURL: normalizedURL,
		httpClient: &http.Client{
			Timeout: time.Duration(testTimeout) * time.Second,
		},
	}

	return client, nil
}

// normalizeURL нормализует URL, удаляя дублирующие протоколы
func normalizeURL(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}

	// Удаляем все префиксы протоколов
	rawURL = strings.TrimPrefix(rawURL, "http://")
	rawURL = strings.TrimPrefix(rawURL, "https://")

	// Добавляем https:// (для production всегда используем HTTPS)
	return "https://" + rawURL
}

// Close закрывает соединение
func (c *TestClient) Close() {
	// HTTP клиент не требует явного закрытия
}

// SetToken устанавливает токен аутентификации
func (c *TestClient) SetToken(token string) {
	c.token = token
}

// makeRequest выполняет HTTP запрос
func (c *TestClient) makeRequest(method, endpoint string, body interface{}, response interface{}) error {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	url := c.baseURL + endpoint
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Устанавливаем заголовки
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	// Выполняем запрос
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Читаем ответ
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Проверяем статус код
	if resp.StatusCode >= 400 {
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	// Парсим ответ
	if err := json.Unmarshal(respBody, response); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return nil
}

// RunTests запускает все тесты
func (c *TestClient) RunTests() {
	fmt.Println("🚀 Запуск тестов для SellerProof Backend")
	fmt.Printf("📡 Подключение к сервису: %s\n", serviceURL)
	fmt.Printf("🔗 Итоговый URL: %s\n", c.baseURL)
	fmt.Printf("⏱️  Таймаут: %d секунд\n", testTimeout)

	if testMode != "" {
		fmt.Printf("🎯 Режим: %s\n", testMode)
	} else {
		fmt.Println("🎯 Режим: все тесты")
	}
	fmt.Println()

	// Тесты аутентификации
	if testMode == "" || testMode == "auth" {
		fmt.Println("🔐 Запуск тестов аутентификации...")
		c.testRegister()
		c.testLogin()
		c.testGetProfile()
		c.testUpdateProfile()
		c.testRefreshToken()
		c.testLogout()
		fmt.Println()
	}

	// Тесты видео
	if testMode == "" || testMode == "video" {
		fmt.Println("📹 Запуск тестов видео...")
		c.testInitiateMultipartUpload()
		c.testGetPartUploadURLs()
		c.testCompleteMultipartUpload()
		c.testGetVideo()
		c.testSearchVideos()
		c.testCreatePublicShareLink()
		c.testGetPublicVideo()
		c.testRevokeShareLink()
		fmt.Println()
	}

	fmt.Println("✅ Все тесты завершены!")
}

// printResult выводит результат теста
func (c *TestClient) printResult(testName string, success bool, details string) {
	status := "❌ ОШИБКА"
	if success {
		status = "✅ УСПЕХ"
	}
	fmt.Printf("[%s] %s\n", status, testName)
	if details != "" {
		fmt.Printf("   %s\n", details)
	}
	fmt.Println()
}

// testRegister тестирует регистрацию пользователя
func (c *TestClient) testRegister() {
	fmt.Println("📝 Тестирование регистрации пользователя...")

	req := map[string]interface{}{
		"email":     fmt.Sprintf("test%d@example.com", time.Now().Unix()),
		"password":  "TestPassword123!",
		"full_name": "Test User",
	}

	var resp map[string]interface{}
	err := c.makeRequest("POST", "/api/v1/auth/register", req, &resp)
	if err != nil {
		c.printResult("Регистрация", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.userID = resp["user_id"].(string)
	c.printResult("Регистрация", true, fmt.Sprintf("ID пользователя: %s, сообщение: %s", resp["user_id"], resp["message"]))
}

// testLogin тестирует вход пользователя
func (c *TestClient) testLogin() {
	fmt.Println("🔐 Тестирование входа пользователя...")

	req := map[string]interface{}{
		"email":    "test@example.com",
		"password": "TestPassword123!",
	}

	var resp map[string]interface{}
	err := c.makeRequest("POST", "/api/v1/auth/login", req, &resp)
	if err != nil {
		c.printResult("Вход", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	data := resp["user"].(map[string]interface{})
	c.token = resp["access_token"].(string)
	c.userID = data["user_id"].(string)
	c.printResult("Вход", true, fmt.Sprintf("Токен получен, пользователь: %s (%s)", data["full_name"], data["email"]))
}

// testGetProfile тестирует получение профиля
func (c *TestClient) testGetProfile() {
	fmt.Println("👤 Тестирование получения профиля...")

	if c.token == "" {
		c.printResult("Получение профиля", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	var resp map[string]interface{}
	err := c.makeRequest("GET", "/api/v1/auth/profile", nil, &resp)
	if err != nil {
		c.printResult("Получение профиля", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	data := resp["user"].(map[string]interface{})
	c.printResult("Получение профиля", true, fmt.Sprintf("Пользователь: %s (%s), роль: %s", data["full_name"], data["email"], data["role"]))
}

// testUpdateProfile тестирует обновление профиля
func (c *TestClient) testUpdateProfile() {
	fmt.Println("✏️ Тестирование обновления профиля...")

	if c.token == "" {
		c.printResult("Обновление профиля", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	req := map[string]interface{}{
		"full_name": "Updated Test User",
	}

	var resp map[string]interface{}
	err := c.makeRequest("PUT", "/api/v1/auth/profile", req, &resp)
	if err != nil {
		c.printResult("Обновление профиля", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	data := resp["user"].(map[string]interface{})
	c.printResult("Обновление профиля", true, fmt.Sprintf("Имя обновлено на: %s", data["full_name"]))
}

// testRefreshToken тестирует обновление токена
func (c *TestClient) testRefreshToken() {
	fmt.Println("🔄 Тестирование обновления токена...")

	if c.token == "" {
		c.printResult("Обновление токена", false, "Требуется refresh токен из ответа входа")
		return
	}

	c.printResult("Обновление токена", false, "Требуется refresh токен из ответа входа")
}

// testLogout тестирует выход пользователя
func (c *TestClient) testLogout() {
	fmt.Println("🚪 Тестирование выхода пользователя...")

	if c.token == "" {
		c.printResult("Выход", false, "Требуется refresh токен из ответа входа")
		return
	}

	req := map[string]interface{}{
		"refresh_token": "dummy-refresh-token",
	}

	var resp map[string]interface{}
	err := c.makeRequest("POST", "/api/v1/auth/logout", req, &resp)
	if err != nil {
		c.printResult("Выход", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Выход", true, fmt.Sprintf("Сообщение: %s", resp["message"]))
}

// testInitiateMultipartUpload тестирует инициализацию загрузки видео
func (c *TestClient) testInitiateMultipartUpload() {
	fmt.Println("📹 Тестирование инициализации загрузки видео...")

	if c.token == "" {
		c.printResult("Инициализация загрузки видео", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	req := map[string]interface{}{
		"file_name":        "test-video.mp4",
		"file_size_bytes":  102400000,
		"duration_seconds": 300,
	}

	var resp map[string]interface{}
	err := c.makeRequest("POST", "/api/v1/video/upload/initiate", req, &resp)
	if err != nil {
		c.printResult("Инициализация загрузки видео", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Инициализация загрузки видео", true, fmt.Sprintf("ID видео: %s, ID загрузки: %s", resp["video_id"], resp["upload_id"]))
}

// testGetPartUploadURLs тестирует получение URL для загрузки частей
func (c *TestClient) testGetPartUploadURLs() {
	fmt.Println("🔗 Тестирование получения URL для загрузки частей...")

	if c.token == "" {
		c.printResult("Получение URL для загрузки частей", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	req := map[string]interface{}{
		"video_id":    "test-video-id",
		"total_parts": 5,
	}

	var resp map[string]interface{}
	err := c.makeRequest("POST", "/api/v1/video/upload/urls", req, &resp)
	if err != nil {
		c.printResult("Получение URL для загрузки частей", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	data := resp["part_urls"].([]interface{})
	c.printResult("Получение URL для загрузки частей", true, fmt.Sprintf("Получено %d URL, истекают: %d", len(data), resp["expires_at"]))
}

// testCompleteMultipartUpload тестирует завершение загрузки видео
func (c *TestClient) testCompleteMultipartUpload() {
	fmt.Println("✅ Тестирование завершения загрузки видео...")

	if c.token == "" {
		c.printResult("Завершение загрузки видео", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	parts := make([]map[string]interface{}, 0)
	for i := 1; i <= 3; i++ {
		parts = append(parts, map[string]interface{}{
			"part_number": i,
			"etag":        fmt.Sprintf("etag-part-%d", i),
		})
	}

	req := map[string]interface{}{
		"video_id": "test-video-id",
		"parts":    parts,
	}

	var resp map[string]interface{}
	err := c.makeRequest("POST", "/api/v1/video/upload/complete", req, &resp)
	if err != nil {
		c.printResult("Завершение загрузки видео", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Завершение загрузки видео", true, fmt.Sprintf("Сообщение: %s, URL видео: %s", resp["message"], resp["video_url"]))
}

// testGetVideo тестирует получение информации о видео
func (c *TestClient) testGetVideo() {
	fmt.Println("📹 Тестирование получения информации о видео...")

	if c.token == "" {
		c.printResult("Получение информации о видео", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	var resp map[string]interface{}
	err := c.makeRequest("GET", "/api/v1/video?video_id=test-video-id", nil, &resp)
	if err != nil {
		c.printResult("Получение информации о видео", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	data := resp["video"].(map[string]interface{})
	c.printResult("Получение информации о видео", true, fmt.Sprintf("Видео: %s, размер: %v байт, статус: %s", data["file_name"], data["file_size_bytes"], data["upload_status"]))
}

// testSearchVideos тестирует поиск видео
func (c *TestClient) testSearchVideos() {
	fmt.Println("🔍 Тестирование поиска видео...")

	if c.token == "" {
		c.printResult("Поиск видео", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	var resp map[string]interface{}
	err := c.makeRequest("GET", "/api/v1/video/search?query=test&page=1&page_size=10", nil, &resp)
	if err != nil {
		c.printResult("Поиск видео", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	data := resp["videos"].([]interface{})
	c.printResult("Поиск видео", true, fmt.Sprintf("Найдено видео: %d, всего: %d", len(data), resp["total_count"]))
}

// testCreatePublicShareLink тестирует создание публичной ссылки
func (c *TestClient) testCreatePublicShareLink() {
	fmt.Println("🔗 Тестирование создания публичной ссылки...")

	if c.token == "" {
		c.printResult("Создание публичной ссылки", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	req := map[string]interface{}{
		"video_id":         "test-video-id",
		"expires_in_hours": 24,
	}

	var resp map[string]interface{}
	err := c.makeRequest("POST", "/api/v1/video/share", req, &resp)
	if err != nil {
		c.printResult("Создание публичной ссылки", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Создание публичной ссылки", true, fmt.Sprintf("URL: %s, истекает: %d", resp["share_url"], resp["expires_at"]))
}

// testGetPublicVideo тестирует получение публичного видео
func (c *TestClient) testGetPublicVideo() {
	fmt.Println("🌍 Тестирование получения публичного видео...")

	var resp map[string]interface{}
	err := c.makeRequest("GET", "/api/v1/video/public?share_token=test-share-token", nil, &resp)
	if err != nil {
		c.printResult("Получение публичного видео", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Получение публичного видео", true, fmt.Sprintf("Файл: %s, размер: %v, URL: %s", resp["file_name"], resp["file_size"], resp["download_url"]))
}

// testRevokeShareLink тестирует отзыв публичной ссылки
func (c *TestClient) testRevokeShareLink() {
	fmt.Println("🚫 Тестирование отзыва публичной ссылки...")

	if c.token == "" {
		c.printResult("Отзыв публичной ссылки", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	req := map[string]interface{}{
		"video_id": "test-video-id",
	}

	var resp map[string]interface{}
	err := c.makeRequest("POST", "/api/v1/video/share/revoke", req, &resp)
	if err != nil {
		c.printResult("Отзыв публичной ссылки", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Отзыв публичной ссылки", true, fmt.Sprintf("Успешно: %v", resp["success"]))
}

// Main функция для запуска тестов
func main() {
	// Читаем URL из переменной окружения, если она установлена (имеет приоритет над Makefile)
	if url := os.Getenv("SERVICE_URL"); url != "" {
		serviceURL = url
	}

	// Читаем таймаут из переменной окружения, если она установлена
	if timeout := os.Getenv("TIMEOUT"); timeout != "" {
		if t, err := strconv.Atoi(timeout); err == nil {
			testTimeout = t
		}
	}

	// Читаем режим тестов из переменной окружения
	if mode := os.Getenv("TEST_MODE"); mode != "" {
		testMode = mode
	}

	client, err := NewTestClient()
	if err != nil {
		log.Fatalf("Ошибка создания клиента: %v", err)
	}
	defer client.Close()

	client.RunTests()
}
