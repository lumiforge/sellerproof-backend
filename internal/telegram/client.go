package telegram

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

type Client struct {
	token  string
	chatID string
	client *http.Client
}

func NewClient() *Client {
	return &Client{
		token:  os.Getenv("TELEGRAM_BOT_TOKEN"),
		chatID: os.Getenv("TELEGRAM_ADMIN_CHAT_ID"),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) SendAlert(msg string) error {
	if c.token == "" || c.chatID == "" {
		return nil
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", c.token)
	vals := url.Values{}
	vals.Set("chat_id", c.chatID)
	vals.Set("text", "🚨 ERROR: "+msg)

	resp, err := c.client.PostForm(apiURL, vals)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}