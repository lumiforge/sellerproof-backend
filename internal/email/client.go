package email

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	appconfig "github.com/lumiforge/sellerproof-backend/internal/config"
)

type Client struct {
	SESClient *sesv2.Client
	Sender    string
	LoginURL  string
}

func NewClient(appCfg *appconfig.Config) *Client {
	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL:           appCfg.SESEndpoint,
			SigningRegion: appCfg.SESRegion,
		}, nil
	})

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolverWithOptions(resolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(appCfg.SESAccessKeyID, appCfg.SESSecretAccessKey, "")),
		config.WithRegion(appCfg.SESRegion),
	)
	if err != nil {
		log.Fatalf("failed to load SES config: %v", err)
	}

	sesClient := sesv2.NewFromConfig(cfg)

	return &Client{
		SESClient: sesClient,
		Sender:    appCfg.EmailFrom,
		LoginURL:  appCfg.AppLoginURL,
	}
}

func (c *Client) SendAuthDetails(ctx context.Context, recipientEmail, username, password string) error {
	subject := "Добро пожаловать в систему"
	body := fmt.Sprintf(
		"Здравствуйте!\n\nДля вас была создана учетная запись в нашей системе.\n\nДанные для входа:\nЛогин: %s\nПароль: %s\n\nВы можете войти в систему по ссылке: %s\n\nЭто письмо сгенерировано автоматически, пожалуйста, не отвечайте на него.",
		username,
		password,
		c.LoginURL,
	)

	input := &sesv2.SendEmailInput{
		FromEmailAddress: &c.Sender,
		Destination: &types.Destination{
			ToAddresses: []string{recipientEmail},
		},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Subject: &types.Content{
					Data: &subject,
				},
				Body: &types.Body{
					Text: &types.Content{
						Data: &body,
					},
				},
			},
		},
	}

	_, err := c.SESClient.SendEmail(ctx, input)
	return err
}

// SendVerificationEmail отправляет email верификации
func (c *Client) SendVerificationEmail(ctx context.Context, toEmail, verificationCode string) (*EmailMessage, error) {
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
		Type:      EmailTypeVerification,
		Recipient: toEmail,
		Subject:   subject,
		Body:      body,
		Status:    EmailStatusSent,
	}

	err := c.sendHTMLEmail(ctx, toEmail, subject, body)
	if err != nil {
		message.Status = EmailStatusFailed
		message.Error = err.Error()
		return message, err
	}

	return message, nil
}

// SendPasswordResetEmail отправляет email для сброса пароля
func (c *Client) SendPasswordResetEmail(ctx context.Context, toEmail, resetToken string, frontendBaseURL string) (*EmailMessage, error) {
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
		Type:      EmailTypePasswordReset,
		Recipient: toEmail,
		Subject:   subject,
		Body:      body,
		Status:    EmailStatusSent,
	}

	err := c.sendHTMLEmail(ctx, toEmail, subject, body)
	if err != nil {
		message.Status = EmailStatusFailed
		message.Error = err.Error()
		return message, err
	}

	return message, nil
}

// SendSubscriptionEmail отправляет email о подписке
func (c *Client) SendSubscriptionEmail(ctx context.Context, toEmail, planName string, isUpgrade bool) (*EmailMessage, error) {
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
		Type:      EmailTypeSubscription,
		Recipient: toEmail,
		Subject:   subject,
		Body:      body,
		Status:    EmailStatusSent,
	}

	err := c.sendHTMLEmail(ctx, toEmail, subject, body)
	if err != nil {
		message.Status = EmailStatusFailed
		message.Error = err.Error()
		return message, err
	}

	return message, nil
}

// sendHTMLEmail отправляет HTML email через SES
func (c *Client) sendHTMLEmail(ctx context.Context, toEmail, subject, htmlBody string) error {
	input := &sesv2.SendEmailInput{
		FromEmailAddress: &c.Sender,
		Destination: &types.Destination{
			ToAddresses: []string{toEmail},
		},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Subject: &types.Content{
					Data: &subject,
				},
				Body: &types.Body{
					Html: &types.Content{
						Data: &htmlBody,
					},
				},
			},
		},
	}

	_, err := c.SESClient.SendEmail(ctx, input)
	return err
}

// IsConfigured проверяет, настроен ли email сервис
func (c *Client) IsConfigured() bool {
	return c.Sender != "" && c.SESClient != nil
}
