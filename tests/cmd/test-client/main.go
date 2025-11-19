package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/lumiforge/sellerproof-backend/proto"
)

// URL вашего сервиса в Yandex Cloud (будет установлен при сборке из Makefile)
var serviceURL string
var testTimeout = 30 // секунды по умолчанию
var testMode = ""    // "auth" или "video" или "" (все тесты)

func init() {
	// Если URL не установлен при сборке, используем значение по умолчанию

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
}

// normalizeURL нормализует URL, добавляя порт если необходимо
func normalizeURL(rawURL string) string {
	// Если URL пустой, возвращаем пустую строку
	if rawURL == "" {
		return rawURL
	}

	// Парсим URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		log.Printf("⚠️  Предупреждение: не удалось разобрать URL '%s': %v", rawURL, err)
		return rawURL
	}

	// Если схема не указана, добавляем https
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}

	// Если порт не указан и это https, добавляем порт 443
	if parsedURL.Port() == "" {
		if parsedURL.Scheme == "https" {
			parsedURL.Host = parsedURL.Host + ":443"
		} else if parsedURL.Scheme == "http" {
			parsedURL.Host = parsedURL.Host + ":80"
		}
	}

	// Для gRPC нам нужен только хост:порт, без схемы
	return parsedURL.Host
}

// TestClient представляет тестовый клиент для gRPC сервиса
type TestClient struct {
	conn   *grpc.ClientConn
	auth   pb.AuthServiceClient
	video  pb.VideoServiceClient
	token  string
	userID string
}

// NewTestClient создает новый тестовый клиент
func NewTestClient() (*TestClient, error) {
	// Нормализуем URL, добавляя порт если необходимо
	normalizedURL := normalizeURL(serviceURL)

	// Определяем тип credentials на основе схемы URL
	var creds credentials.TransportCredentials
	if serviceURL != "" {
		parsedURL, err := url.Parse(serviceURL)
		if err == nil && parsedURL.Scheme == "https" {
			// Для HTTPS используем TLS credentials
			creds = credentials.NewTLS(&tls.Config{
				InsecureSkipVerify: true, // Для тестирования пропускаем проверку сертификата
			})
		} else {
			// Для HTTP или без схемы используем insecure credentials
			creds = insecure.NewCredentials()
		}
	} else {
		creds = insecure.NewCredentials()
	}

	// Устанавливаем соединение с gRPC сервером
	conn, err := grpc.Dial(normalizedURL, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к серверу: %v", err)
	}

	client := &TestClient{
		conn:  conn,
		auth:  pb.NewAuthServiceClient(conn),
		video: pb.NewVideoServiceClient(conn),
	}

	return client, nil
}

// Close закрывает соединение
func (c *TestClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// RunTests запускает все тесты
func (c *TestClient) RunTests() {
	// Нормализуем URL для подключения
	normalizedURL := normalizeURL(serviceURL)

	// Создаем полный URL для отображения
	displayURL := serviceURL
	if displayURL == "" {
		displayURL = "не указан"
	}

	fmt.Println("🚀 Запуск тестов для SellerProof Backend")
	fmt.Printf("📡 Подключение к сервису: %s\n", displayURL)
	fmt.Printf("🔗 Адрес для gRPC: %s\n", normalizedURL)
	fmt.Printf("⏱️  Таймаут: %d секунд\n", testTimeout)

	if testMode != "" {
		fmt.Printf("🎯 Режим: %s\n\n", testMode)
	} else {
		fmt.Println("🎯 Режим: все тесты\n")
	}

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

	req := &pb.RegisterRequest{
		Email:    fmt.Sprintf("test%d@example.com", time.Now().Unix()),
		Password: "TestPassword123!",
		FullName: "Test User",
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	resp, err := c.auth.Register(ctx, req)
	if err != nil {
		c.printResult("Регистрация", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.userID = resp.UserId
	c.printResult("Регистрация", true, fmt.Sprintf("ID пользователя: %s, сообщение: %s", resp.UserId, resp.Message))
}

// testLogin тестирует вход пользователя
func (c *TestClient) testLogin() {
	fmt.Println("🔐 Тестирование входа пользователя...")

	req := &pb.LoginRequest{
		Email:    "test@example.com", // Используем существующий email для теста
		Password: "TestPassword123!",
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	resp, err := c.auth.Login(ctx, req)
	if err != nil {
		c.printResult("Вход", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.token = resp.AccessToken
	c.userID = resp.User.UserId
	c.printResult("Вход", true, fmt.Sprintf("Токен получен, пользователь: %s (%s)", resp.User.FullName, resp.User.Email))
}

// testGetProfile тестирует получение профиля
func (c *TestClient) testGetProfile() {
	fmt.Println("👤 Тестирование получения профиля...")

	if c.token == "" {
		c.printResult("Получение профиля", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	// Добавляем токен в метаданные
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", c.token))

	req := &pb.GetProfileRequest{}
	resp, err := c.auth.GetProfile(ctx, req)
	if err != nil {
		c.printResult("Получение профиля", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Получение профиля", true, fmt.Sprintf("Пользователь: %s (%s), роль: %s", resp.User.FullName, resp.User.Email, resp.User.Role))
}

// testUpdateProfile тестирует обновление профиля
func (c *TestClient) testUpdateProfile() {
	fmt.Println("✏️ Тестирование обновления профиля...")

	if c.token == "" {
		c.printResult("Обновление профиля", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	// Добавляем токен в метаданные
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", c.token))

	req := &pb.UpdateProfileRequest{
		FullName: "Updated Test User",
	}

	resp, err := c.auth.UpdateProfile(ctx, req)
	if err != nil {
		c.printResult("Обновление профиля", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Обновление профиля", true, fmt.Sprintf("Имя обновлено на: %s", resp.User.FullName))
}

// testRefreshToken тестирует обновление токена
func (c *TestClient) testRefreshToken() {
	fmt.Println("🔄 Тестирование обновления токена...")

	// Для этого теста нужен refresh токен, который мы получаем при входе
	// В реальном сценарии мы бы сохранили refresh токен из ответа входа
	c.printResult("Обновление токена", false, "Требуется refresh токен из ответа входа")
}

// testLogout тестирует выход пользователя
func (c *TestClient) testLogout() {
	fmt.Println("🚪 Тестирование выхода пользователя...")

	// Для этого теста нужен refresh токен
	c.printResult("Выход", false, "Требуется refresh токен из ответа входа")
}

// testInitiateMultipartUpload тестирует инициализацию загрузки видео
func (c *TestClient) testInitiateMultipartUpload() {
	fmt.Println("📹 Тестирование инициализации загрузки видео...")

	if c.token == "" {
		c.printResult("Инициализация загрузки видео", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	// Добавляем токен в метаданные
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", c.token))

	req := &pb.InitiateMultipartUploadRequest{
		FileName:        "test-video.mp4",
		FileSizeBytes:   102400000, // 100MB
		DurationSeconds: 300,       // 5 минут
	}

	resp, err := c.video.InitiateMultipartUpload(ctx, req)
	if err != nil {
		c.printResult("Инициализация загрузки видео", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Инициализация загрузки видео", true, fmt.Sprintf("ID видео: %s, ID загрузки: %s", resp.VideoId, resp.UploadId))
}

// testGetPartUploadURLs тестирует получение URL для загрузки частей
func (c *TestClient) testGetPartUploadURLs() {
	fmt.Println("🔗 Тестирование получения URL для загрузки частей...")

	if c.token == "" {
		c.printResult("Получение URL для загрузки частей", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	// Добавляем токен в метаданные
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", c.token))

	req := &pb.GetPartUploadURLsRequest{
		VideoId:    "test-video-id", // Используем тестовый ID
		TotalParts: 5,
	}

	resp, err := c.video.GetPartUploadURLs(ctx, req)
	if err != nil {
		c.printResult("Получение URL для загрузки частей", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Получение URL для загрузки частей", true, fmt.Sprintf("Получено %d URL, истекают: %d", len(resp.PartUrls), resp.ExpiresAt))
}

// testCompleteMultipartUpload тестирует завершение загрузки видео
func (c *TestClient) testCompleteMultipartUpload() {
	fmt.Println("✅ Тестирование завершения загрузки видео...")

	if c.token == "" {
		c.printResult("Завершение загрузки видео", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	// Добавляем токен в метаданные
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", c.token))

	// Создаем тестовые части
	parts := make([]*pb.CompletedPart, 0)
	for i := 1; i <= 3; i++ {
		parts = append(parts, &pb.CompletedPart{
			PartNumber: int32(i),
			Etag:       fmt.Sprintf("etag-part-%d", i),
		})
	}

	req := &pb.CompleteMultipartUploadRequest{
		VideoId: "test-video-id", // Используем тестовый ID
		Parts:   parts,
	}

	resp, err := c.video.CompleteMultipartUpload(ctx, req)
	if err != nil {
		c.printResult("Завершение загрузки видео", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Завершение загрузки видео", true, fmt.Sprintf("Сообщение: %s, URL видео: %s", resp.Message, resp.VideoUrl))
}

// testGetVideo тестирует получение информации о видео
func (c *TestClient) testGetVideo() {
	fmt.Println("📹 Тестирование получения информации о видео...")

	if c.token == "" {
		c.printResult("Получение информации о видео", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	// Добавляем токен в метаданные
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", c.token))

	req := &pb.GetVideoRequest{
		VideoId: "test-video-id", // Используем тестовый ID
	}

	resp, err := c.video.GetVideo(ctx, req)
	if err != nil {
		c.printResult("Получение информации о видео", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Получение информации о видео", true, fmt.Sprintf("Видео: %s, размер: %d байт, статус: %s", resp.Video.FileName, resp.Video.FileSizeBytes, resp.Video.UploadStatus))
}

// testSearchVideos тестирует поиск видео
func (c *TestClient) testSearchVideos() {
	fmt.Println("🔍 Тестирование поиска видео...")

	if c.token == "" {
		c.printResult("Поиск видео", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	// Добавляем токен в метаданные
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", c.token))

	req := &pb.SearchVideosRequest{
		Query:    "test",
		Page:     1,
		PageSize: 10,
	}

	resp, err := c.video.SearchVideos(ctx, req)
	if err != nil {
		c.printResult("Поиск видео", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Поиск видео", true, fmt.Sprintf("Найдено видео: %d, всего: %d", len(resp.Videos), resp.TotalCount))
}

// testCreatePublicShareLink тестирует создание публичной ссылки
func (c *TestClient) testCreatePublicShareLink() {
	fmt.Println("🔗 Тестирование создания публичной ссылки...")

	if c.token == "" {
		c.printResult("Создание публичной ссылки", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	// Добавляем токен в метаданные
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", c.token))

	req := &pb.CreateShareLinkRequest{
		VideoId:        "test-video-id", // Используем тестовый ID
		ExpiresInHours: 24,
	}

	resp, err := c.video.CreatePublicShareLink(ctx, req)
	if err != nil {
		c.printResult("Создание публичной ссылки", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Создание публичной ссылки", true, fmt.Sprintf("URL: %s, истекает: %d", resp.ShareUrl, resp.ExpiresAt))
}

// testGetPublicVideo тестирует получение публичного видео
func (c *TestClient) testGetPublicVideo() {
	fmt.Println("🌍 Тестирование получения публичного видео...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	req := &pb.GetPublicVideoRequest{
		ShareToken: "test-share-token", // Используем тестовый токен
	}

	resp, err := c.video.GetPublicVideo(ctx, req)
	if err != nil {
		c.printResult("Получение публичного видео", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Получение публичного видео", true, fmt.Sprintf("Файл: %s, размер: %d, URL: %s", resp.FileName, resp.FileSize, resp.DownloadUrl))
}

// testRevokeShareLink тестирует отзыв публичной ссылки
func (c *TestClient) testRevokeShareLink() {
	fmt.Println("🚫 Тестирование отзыва публичной ссылки...")

	if c.token == "" {
		c.printResult("Отзыв публичной ссылки", false, "Токен отсутствует, необходимо сначала войти")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(testTimeout)*time.Second)
	defer cancel()

	// Добавляем токен в метаданные
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", c.token))

	req := &pb.RevokeShareLinkRequest{
		VideoId: "test-video-id", // Используем тестовый ID
	}

	resp, err := c.video.RevokeShareLink(ctx, req)
	if err != nil {
		c.printResult("Отзыв публичной ссылки", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Отзыв публичной ссылки", true, fmt.Sprintf("Успешно: %t", resp.Success))
}

// Main функция для запуска тестов
func main() {
	client, err := NewTestClient()
	if err != nil {
		log.Fatalf("Ошибка создания клиента: %v", err)
	}
	defer client.Close()

	client.RunTests()
}
