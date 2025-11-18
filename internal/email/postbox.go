package email

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/smtp"
	"time"

	"github.com/google/uuid"
	"github.com/lumiforge/sellerproof-backend/internal/config"
)

// PostboxClient клиент для работы с Yandex Cloud Postbox
type PostboxClient struct {
	Host      string
	Port      string
	Username  string // ACCESS_KEY_ID
	Password  string // SECRET_ACCESS_KEY
	FromEmail string
}

// NewPostboxClient создает новый Postbox клиент
func NewPostboxClient(cfg *config.Config) *PostboxClient {
	return &PostboxClient{
		Host:      "smtp.postbox.cloud.yandex.net",
		Port:      "587",
		Username:  cfg.PostboxAccessKeyID,
		Password:  cfg.PostboxSecretAccessKey,
		FromEmail: cfg.PostboxFromEmail,
	}
}

// EmailType представляет тип email
type EmailType string

const (
	EmailTypeVerification  EmailType = "verification"
	EmailTypePasswordReset EmailType = "password_reset"
	EmailTypeSubscription  EmailType = "subscription"
)

// EmailStatus представляет статус email
type EmailStatus string

const (
	EmailStatusSent      EmailStatus = "sent"
	EmailStatusDelivered EmailStatus = "delivered"
	EmailStatusBounced   EmailStatus = "bounced"
	EmailStatusFailed    EmailStatus = "failed"
)

// EmailMessage представляет email сообщение
type EmailMessage struct {
	ID        string      `json:"id"`
	UserID    string      `json:"user_id"`
	Type      EmailType   `json:"type"`
	Recipient string      `json:"recipient"`
	Subject   string      `json:"subject"`
	Body      string      `json:"body"`
	Status    EmailStatus `json:"status"`
	SentAt    time.Time   `json:"sent_at"`
	MessageID string      `json:"message_id"`
	Error     string      `json:"error,omitempty"`
}

// GenerateVerificationCode генерирует 6-значный код верификации
func GenerateVerificationCode() (string, error) {
	bytes := make([]byte, 3) // 6 символов в hex
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// SendVerificationEmail отправляет email верификации
func (p *PostboxClient) SendVerificationEmail(toEmail, verificationCode string) (*EmailMessage, error) {
	subject := "Подтвердите email - SellerProof"
	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>Добро пожаловать в SellerProof!</h2>
			<p>Ваш код верификации: <strong>%s</strong></p>
			<p>Код действителен 24 часа.</p>
			<p>Если вы не регистрировались, проигнорируйте это письмо.</p>
		</body>
		</html>
	`, verificationCode)

	message := &EmailMessage{
		ID:        uuid.New().String(),
		Type:      EmailTypeVerification,
		Recipient: toEmail,
		Subject:   subject,
		Body:      body,
		Status:    EmailStatusSent,
		SentAt:    time.Now(),
	}

	err := p.sendEmail(toEmail, subject, body)
	if err != nil {
		message.Status = EmailStatusFailed
		message.Error = err.Error()
		return message, err
	}

	return message, nil
}

// SendPasswordResetEmail отправляет email для сброса пароля
func (p *PostboxClient) SendPasswordResetEmail(toEmail, resetToken string, frontendBaseURL string) (*EmailMessage, error) {
	subject := "Сброс пароля - SellerProof"
	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>Сброс пароля в SellerProof</h2>
			<p>Вы запросили сброс пароля. Перейдите по ссылке ниже:</p>
			<p><a href="%s/reset-password?token=%s">Сбросить пароль</a></p>
			<p>Ссылка действительна 1 час.</p>
			<p>Если вы не запрашивали сброс пароля, проигнорируйте это письмо.</p>
		</body>
		</html>
	`, frontendBaseURL, resetToken)

	message := &EmailMessage{
		ID:        uuid.New().String(),
		Type:      EmailTypePasswordReset,
		Recipient: toEmail,
		Subject:   subject,
		Body:      body,
		Status:    EmailStatusSent,
		SentAt:    time.Now(),
	}

	err := p.sendEmail(toEmail, subject, body)
	if err != nil {
		message.Status = EmailStatusFailed
		message.Error = err.Error()
		return message, err
	}

	return message, nil
}

// SendSubscriptionEmail отправляет email о подписке
func (p *PostboxClient) SendSubscriptionEmail(toEmail, planName string, isUpgrade bool) (*EmailMessage, error) {
	var subject, action string
	if isUpgrade {
		subject = "Подписка обновлена - SellerProof"
		action = "обновлена"
	} else {
		subject = "Добро пожаловать в SellerProof!"
		action = "активирована"
	}

	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>Ваша подписка %s</h2>
			<p>Ваша подписка на тариф "%s" успешно %s.</p>
			<p>Спасибо за использование SellerProof!</p>
		</body>
		</html>
	`, action, planName, action)

	message := &EmailMessage{
		ID:        uuid.New().String(),
		Type:      EmailTypeSubscription,
		Recipient: toEmail,
		Subject:   subject,
		Body:      body,
		Status:    EmailStatusSent,
		SentAt:    time.Now(),
	}

	err := p.sendEmail(toEmail, subject, body)
	if err != nil {
		message.Status = EmailStatusFailed
		message.Error = err.Error()
		return message, err
	}

	return message, nil
}

// sendEmail отправляет email через SMTP
func (p *PostboxClient) sendEmail(toEmail, subject, body string) error {
	if p.Username == "" || p.Password == "" || p.FromEmail == "" {
		return fmt.Errorf("Postbox credentials not configured")
	}

	message := fmt.Sprintf("From: %s\r\n", p.FromEmail) +
		fmt.Sprintf("To: %s\r\n", toEmail) +
		fmt.Sprintf("Subject: %s\r\n", subject) +
		"MIME-version: 1.0;\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\";\r\n\r\n" +
		body

	auth := smtp.PlainAuth("", p.Username, p.Password, p.Host)
	err := smtp.SendMail(
		p.Host+":"+p.Port,
		auth,
		p.FromEmail,
		[]string{toEmail},
		[]byte(message),
	)

	return err
}

// ValidateEmail проверяет корректность email адреса
func ValidateEmail(email string) bool {
	// Простая валидация email
	if len(email) < 5 || len(email) > 254 {
		return false
	}

	// В реальном приложении здесь должна быть более сложная валидация
	// или использование regexp
	return true
}

// GenerateSecureToken генерирует безопасный токен
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// EmailConfig представляет конфигурацию email сервиса
type EmailConfig struct {
	AccessKeyID     string
	SecretAccessKey string
	FromEmail       string
	FrontendBaseURL string
}

// LoadEmailConfig загружает конфигурацию из переменных окружения
func LoadEmailConfig(cfg *config.Config) *EmailConfig {
	return &EmailConfig{
		AccessKeyID:     cfg.PostboxAccessKeyID,
		SecretAccessKey: cfg.PostboxSecretAccessKey,
		FromEmail:       cfg.PostboxFromEmail,
		FrontendBaseURL: cfg.FrontendBaseURL,
	}
}

// IsConfigured проверяет, настроен ли email сервис
func (p *PostboxClient) IsConfigured() bool {
	return p.Username != "" && p.Password != "" && p.FromEmail != ""
}
