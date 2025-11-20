package main

import (
	"fmt"
)

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
	c.refreshToken = resp["refresh_token"].(string)
	c.userID = data["user_id"].(string)
	c.printResult("Вход", true, fmt.Sprintf("Токен получен, пользователь: %s (%s)", data["full_name"], data["email"]))
}

// testLoginWithCode тестирует вход пользователя с кодом верификации
func (c *TestClient) testLoginWithCode() {
	fmt.Println("🔐 Тестирование верификации email и входа...")

	if testEmailAddress == "" {
		c.printResult("Вход с кодом", false, "Требуется TEST_EMAIL_ADDRESS")
		return
	}

	if verificationCode == "" {
		c.printResult("Вход с кодом", false, "Требуется VERIFICATION_CODE")
		return
	}

	// Шаг 1: Верификация email с кодом
	fmt.Println("   📧 Шаг 1: Верификация email...")
	verifyReq := map[string]interface{}{
		"email": testEmailAddress,
		"code":  verificationCode,
	}

	fmt.Printf("   📧 Email: %s\n", testEmailAddress)
	fmt.Printf("   🔑 Код: %s\n", verificationCode)

	var verifyResp map[string]interface{}
	err := c.makeRequest("POST", "/api/v1/auth/verify-email", verifyReq, &verifyResp)
	if err != nil {
		c.printResult("Верификация email", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	c.printResult("Верификация email", true, fmt.Sprintf("Сообщение: %s", verifyResp["message"]))

	// Шаг 2: Вход с паролем
	fmt.Println("   🔐 Шаг 2: Вход с паролем...")
	loginReq := map[string]interface{}{
		"email":    testEmailAddress,
		"password": "TestPassword123!", // Используем тот же пароль, что и при регистрации
	}

	var resp map[string]interface{}
	err = c.makeRequest("POST", "/api/v1/auth/login", loginReq, &resp)
	if err != nil {
		c.printResult("Вход после верификации", false, fmt.Sprintf("Ошибка: %v", err))
		return
	}

	data := resp["user"].(map[string]interface{})
	c.token = resp["access_token"].(string)
	c.refreshToken = resp["refresh_token"].(string)
	c.userID = data["user_id"].(string)
	c.printResult("Вход после верификации", true, fmt.Sprintf("Токен получен, пользователь: %s (%s)", data["full_name"], data["email"]))
}

// testLoginInvalidCredentials тестирует вход с неверными учетными данными
func (c *TestClient) testLoginInvalidCredentials() {
	fmt.Println("   🔐 Тест: Вход с неверным паролем...")

	req := map[string]interface{}{
		"email":    "test@example.com",
		"password": "WrongPassword123!",
	}

	var resp map[string]interface{}
	err := c.makeRequest("POST", "/api/v1/auth/login", req, &resp)
	if err == nil {
		c.printResult("Вход с неверным паролем", false, "Ожидалась ошибка, но получен успех")
		return
	}

	c.printResult("Вход с неверным паролем", true, "Получена ожидаемая ошибка")
}

// testNegativeLoginScenarios запускает негативные тесты для входа
func (c *TestClient) testNegativeLoginScenarios() {
	fmt.Println("⛔ Запуск негативных тестов входа...")
	c.testLoginInvalidCredentials()
	fmt.Println()
}
