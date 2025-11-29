package email

import (
	"context"
	"fmt"
	"html"
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

// SendInvitationEmail отправляет email приглашения пользователю
func (c *Client) SendInvitationEmail(ctx context.Context, email, inviteCode, orgName string) (*EmailMessage, error) {
	safeOrgName := html.EscapeString(orgName)
	subject := fmt.Sprintf("Вы приглашены в организацию %s на SellerProof", safeOrgName)

	inviteLink := fmt.Sprintf("%s?invite_code=%s", c.LoginURL, inviteCode)

	body := fmt.Sprintf(`
		<html>
		<head>
			<meta charset="UTF-8">
		</head>
		<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
			<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
				<h2>Приглашение в SellerProof</h2>
				<p>Здравствуйте!</p>
				<p>Вы были приглашены присоединиться к организации <strong>%s</strong> на платформе SellerProof.</p>
				
				<p style="margin-top: 30px;">
					<a href="%s" style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block;">
						Принять приглашение
					</a>
				</p>

				<p style="margin-top: 20px; font-size: 14px; color: #666;">
					Или перейдите по ссылке: <a href="%s">%s</a>
				</p>

				<p style="margin-top: 30px; border-top: 1px solid #ddd; padding-top: 20px; font-size: 12px; color: #999;">
					Это письмо сгенерировано автоматически. Пожалуйста, не отвечайте на него.
				</p>
			</div>
		</body>
		</html>
	`, orgName, inviteLink, inviteLink, inviteLink)

	message := &EmailMessage{
		Type:      EmailTypeInvitation,
		Recipient: email,
		Subject:   subject,
		Body:      body,
		Status:    EmailStatusSent,
	}

	err := c.sendHTMLEmail(ctx, email, subject, body)
	if err != nil {
		message.Status = EmailStatusFailed
		message.Error = err.Error()
		return message, err
	}

	return message, nil
}
