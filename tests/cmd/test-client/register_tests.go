package main

import (
	"fmt"
	"strings"
	"time"
)

// testRegister тестирует регистрацию пользователя
func (c *TestClient) testRegister() {
	fmt.Println("📝 Тестирование регистрации пользователя...")

	// ### Основные проверки ###

	// **Валидация данных:**
	// Проверить случаи с некорректным email, слишком коротким/длинным паролем, пустым или необычным именем
	fmt.Println("   🔍 Тесты валидации данных...")

	// Тест 1: Некорректный email
	fmt.Println("      📧 Тест: Некорректный email...")
	invalidEmailReq := map[string]interface{}{
		"email":             "invalid-email",
		"password":          "TestPassword123!",
		"full_name":         "Test User",
		"organization_name": "Test Organization",
	}
	_, err := c.makeRequestExpectError("POST", "/api/v1/auth/register", invalidEmailReq, 400)
	if err != nil {
		c.printResult("Валидация некорректного email", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("Валидация некорректного email", true, "Получена ожидаемая ошибка 400")
	}

	// Тест 2: Слишком короткий пароль
	fmt.Println("      🔐 Тест: Слишком короткий пароль...")
	shortPasswordReq := map[string]interface{}{
		"email":             fmt.Sprintf("test%d@example.com", time.Now().Unix()),
		"password":          "123",
		"full_name":         "Test User",
		"organization_name": "Test Organization",
	}
	_, err = c.makeRequestExpectError("POST", "/api/v1/auth/register", shortPasswordReq, 400)
	if err != nil {
		c.printResult("Валидация короткого пароля", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("Валидация короткого пароля", true, "Получена ожидаемая ошибка 400")
	}

	// Тест 3: Слишком длинный пароль
	fmt.Println("      🔐 Тест: Слишком длинный пароль...")
	longPassword := strings.Repeat("a", 200) // 200 символов
	longPasswordReq := map[string]interface{}{
		"email":             fmt.Sprintf("test%d@example.com", time.Now().Unix()),
		"password":          longPassword,
		"full_name":         "Test User",
		"organization_name": "Test Organization",
	}
	_, err = c.makeRequestExpectError("POST", "/api/v1/auth/register", longPasswordReq, 400)
	if err != nil {
		c.printResult("Валидация длинного пароля", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("Валидация длинного пароля", true, "Получена ожидаемая ошибка 400")
	}

	// Тест 4: Пустое имя
	fmt.Println("      👤 Тест: Пустое имя...")
	emptyNameReq := map[string]interface{}{
		"email":             fmt.Sprintf("test%d@example.com", time.Now().Unix()),
		"password":          "TestPassword123!",
		"full_name":         "",
		"organization_name": "Test Organization",
	}
	_, err = c.makeRequestExpectError("POST", "/api/v1/auth/register", emptyNameReq, 400)
	if err != nil {
		c.printResult("Валидация пустого имени", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("Валидация пустого имени", true, "Получена ожидаемая ошибка 400")
	}

	// Тест 5: Необычное имя (специальные символы)
	fmt.Println("      👤 Тест: Необычное имя со специальными символами...")
	unusualNameReq := map[string]interface{}{
		"email":             fmt.Sprintf("test%d@example.com", time.Now().Unix()),
		"password":          "TestPassword123!",
		"full_name":         "<script>alert('xss')</script>",
		"organization_name": "Test Organization",
	}
	_, err = c.makeRequestExpectError("POST", "/api/v1/auth/register", unusualNameReq, 400)
	if err != nil {
		c.printResult("Валидация необычного имени", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("Валидация необычного имени", true, "Получена ожидаемая ошибка 400")
	}

	// Тест 6: Слишком длинное имя
	fmt.Println("      👤 Тест: Слишком длинное имя...")
	longName := strings.Repeat("a", 300) // 300 символов
	longNameReq := map[string]interface{}{
		"email":             fmt.Sprintf("test%d@example.com", time.Now().Unix()),
		"password":          "TestPassword123!",
		"full_name":         longName,
		"organization_name": "Test Organization",
	}
	_, err = c.makeRequestExpectError("POST", "/api/v1/auth/register", longNameReq, 400)
	if err != nil {
		c.printResult("Валидация длинного имени", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("Валидация длинного имени", true, "Получена ожидаемая ошибка 400")
	}

	// Тест 7: Слишком длинный email
	fmt.Println("      📧 Тест: Слишком длинный email...")
	longEmail := fmt.Sprintf("test%d%s@example.com", time.Now().Unix(), strings.Repeat("a", 300))
	longEmailReq := map[string]interface{}{
		"email":             longEmail,
		"password":          "TestPassword123!",
		"full_name":         "Test User",
		"organization_name": "Test Organization",
	}
	_, err = c.makeRequestExpectError("POST", "/api/v1/auth/register", longEmailReq, 400)
	if err != nil {
		c.printResult("Валидация длинного email", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("Валидация длинного email", true, "Получена ожидаемая ошибка 400")
	}

	// **Проверка формата запроса:**
	// Отправка некорректного JSON, отсутствие обязательных полей
	fmt.Println("   📋 Тесты формата запроса...")

	// Тест 8: Некорректный JSON
	fmt.Println("      📄 Тест: Некорректный JSON...")
	invalidJSON := `{"email": "test@example.com", "password": "TestPassword123!", "full_name": "Test User", "organization_name": "Test Organization"`
	err = c.makeRequestWithRawBody("POST", "/api/v1/auth/register", invalidJSON, nil)
	if err == nil {
		c.printResult("Некорректный JSON", false, "Ожидалась ошибка, но получен успех")
	} else {
		c.printResult("Некорректный JSON", true, "Получена ожидаемая ошибка")
	}

	// Тест 9: Отсутствие обязательных полей
	fmt.Println("      📄 Тест: Отсутствие обязательных полей...")
	missingFieldsReq := map[string]interface{}{
		"email": "test@example.com",
		// отсутствуют password, full_name, organization_name
	}
	_, err = c.makeRequestExpectError("POST", "/api/v1/auth/register", missingFieldsReq, 400)
	if err != nil {
		c.printResult("Отсутствие обязательных полей", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("Отсутствие обязательных полей", true, "Получена ожидаемая ошибка 400")
	}

	// ### Безопасность ###

	// **SQL инъекции:**
	// Проверить что endpoint устойчив к попыткам инъекции через email/имя/пароль
	fmt.Println("   🔒 Тесты безопасности (SQL инъекции)...")

	// Тест 10: SQL инъекция через email
	fmt.Println("      💉 Тест: SQL инъекция через email...")
	sqlInjectionEmailReq := map[string]interface{}{
		"email":             "test@example.com'; DROP TABLE users; --",
		"password":          "TestPassword123!",
		"full_name":         "Test User",
		"organization_name": "Test Organization",
	}
	_, err = c.makeRequestExpectError("POST", "/api/v1/auth/register", sqlInjectionEmailReq, 400)
	if err != nil {
		c.printResult("SQL инъекция через email", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("SQL инъекция через email", true, "Получена ожидаемая ошибка 400")
	}

	// Тест 11: SQL инъекция через имя
	fmt.Println("      💉 Тест: SQL инъекция через имя...")
	sqlInjectionNameReq := map[string]interface{}{
		"email":             fmt.Sprintf("test%d@example.com", time.Now().Unix()),
		"password":          "TestPassword123!",
		"full_name":         "'; DROP TABLE users; --",
		"organization_name": "Test Organization",
	}
	_, err = c.makeRequestExpectError("POST", "/api/v1/auth/register", sqlInjectionNameReq, 400)
	if err != nil {
		c.printResult("SQL инъекция через имя", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("SQL инъекция через имя", true, "Получена ожидаемая ошибка 400")
	}

	// Тест 12: SQL инъекция через пароль
	fmt.Println("      💉 Тест: SQL инъекция через пароль...")
	sqlInjectionPasswordReq := map[string]interface{}{
		"email":             fmt.Sprintf("test%d@example.com", time.Now().Unix()),
		"password":          "'; DROP TABLE users; --",
		"full_name":         "Test User",
		"organization_name": "Test Organization",
	}
	_, err = c.makeRequestExpectError("POST", "/api/v1/auth/register", sqlInjectionPasswordReq, 400)
	if err != nil {
		c.printResult("SQL инъекция через пароль", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("SQL инъекция через пароль", true, "Получена ожидаемая ошибка 400")
	}

	// **Корректная регистрация:**
	// Передать валидные email, пароль и имя, убедиться, что пользователь создаётся
	fmt.Println("   ✅ Тест корректной регистрации...")

	// Тест 13: Корректная регистрация
	fmt.Println("      📝 Тест: Корректная регистрация...")
	validEmail := testEmailAddress
	if validEmail == "" {
		validEmail = fmt.Sprintf("test%d@example.com", time.Now().Unix())
	}

	validReq := map[string]interface{}{
		"email":             validEmail,
		"password":          "TestPassword123!",
		"full_name":         "Test User",
		"organization_name": "Test Organization",
	}

	fmt.Printf("   📧 Регистрация email: %s\n", validEmail)

	var resp map[string]interface{}
	err = c.makeRequest("POST", "/api/v1/auth/register", validReq, &resp)
	if err != nil {
		c.printResult("Корректная регистрация", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	// Проверяем наличие ожидаемых полей в ответе
	userID, hasUserID := resp["user_id"]
	message, hasMessage := resp["message"]
	emailVerified, hasEmailVerified := resp["email_verified"]

	if !hasUserID || !hasMessage {
		c.printResult("Корректная регистрация", false, "Отсутствуют обязательные поля в ответе")
		return
	}

	c.userID = userID.(string)
	details := fmt.Sprintf("ID пользователя: %s, сообщение: %s", userID, message)
	if hasEmailVerified {
		details += fmt.Sprintf(", email верифицирован: %v", emailVerified)
	}
	c.printResult("Корректная регистрация", true, details)

	// **Дублирующий email:**
	// Попробовать зарегистрировать пользователя с уже существующим email
	fmt.Println("   🔄 Тест дублирующего email...")

	// Тест 14: Дублирующий email
	fmt.Println("      📧 Тест: Дублирующий email...")
	duplicateReq := map[string]interface{}{
		"email":             validEmail, // Используем тот же email
		"password":          "AnotherPassword123!",
		"full_name":         "Another User",
		"organization_name": "Another Organization",
	}

	_, err = c.makeRequestExpectError("POST", "/api/v1/auth/register", duplicateReq, 409)
	if err != nil {
		c.printResult("Дублирующий email", false, fmt.Sprintf("Ошибка: %v", err))
	} else {
		c.printResult("Дублирующий email", true, "Получена ожидаемая ошибка 409")
	}
}

// runRegistrationTests запускает тесты, связанные с регистрацией
func (c *TestClient) runRegistrationTests() {
	// Режим регистрации (часть 1)
	if testMode == "register" {
		fmt.Println("📝 Запуск регистрации...")
		c.testRegister()
		fmt.Println()
		fmt.Println("✅ Регистрация завершена!")
		fmt.Println("📧 Проверьте email и скопируйте код верификации в переменную received_code в Makefile")
		fmt.Println("💡 Затем запустите: make test-login")
		return
	}

	// Тесты аутентификации (включая регистрацию)
	if testMode == "" || testMode == "auth" {
		fmt.Println("🔐 Запуск тестов аутентификации...")
		c.testRegister()
		fmt.Println()
	}
}
