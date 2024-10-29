package mailer

import (
	"bytes"
	"collectihub/internal/config"
	"collectihub/internal/constants"
	"errors"
	"fmt"
	"html/template"
	"os"

	"github.com/wneessen/go-mail"

	"github.com/rs/zerolog"
)

type Mailer struct {
	username    string
	password    string
	host        string
	port        int
	baseUrl     string
	deepLinkUrl string
	logger      *zerolog.Logger
}

type Mail struct {
	Sender   string
	To       []string
	Subject  string
	Body     string
	BodyType mail.ContentType
}

func New(cfg config.Config, l *zerolog.Logger) *Mailer {
	return &Mailer{
		username:    cfg.MailerUsername,
		password:    cfg.MailerPassword,
		host:        cfg.MailerSmtpHost,
		port:        cfg.MailerSmtpPort,
		baseUrl:     cfg.BaseUrl,
		deepLinkUrl: cfg.DeepLinkUrl,
		logger:      l,
	}
}

func getHtmlTemplate(path string) (*template.Template, error) {
	rawHtml, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("error during reading email template")
	}

	t, err := template.New("account-verification").Parse(string(rawHtml))
	if err != nil {
		return nil, errors.New("error during parsing email template")
	}

	return t, nil
}

func parseHtmlTemplate(t *template.Template, data interface{}) (string, error) {
	var htmlBuffer bytes.Buffer

	if err := t.Execute(&htmlBuffer, data); err != nil {
		return "", errors.New("error during executing email template")
	}

	return htmlBuffer.String(), nil
}

func (ml *Mailer) SendAccountVerificationEmail(to string, key string, name string) error {
	t, err := getHtmlTemplate(constants.AccountVerificationHtmlTemplatePath)
	if err != nil {
		ml.logger.Err(err).Msgf("Error during reading email template")
		return err
	}

	link := template.URL(fmt.Sprintf("%sverify-account/%s", ml.deepLinkUrl, key))

	data := struct {
		Link template.URL
		Name string
	}{
		Link: link,
		Name: name,
	}

	html, err := parseHtmlTemplate(t, data)

	ml.logger.Debug().Msgf("Sending account verification email to: %s", to)

	if err = ml.sendMail(Mail{
		Sender:   ml.username,
		To:       []string{to},
		Subject:  "CollectiHub - Account verification",
		BodyType: mail.TypeTextHTML,
		Body:     html,
	}); err != nil {
		ml.logger.Err(err).Msgf("Error during sending of mail")
	}

	return err
}

func (ml *Mailer) SendPasswordResetVerificationEmail(to string, key string, name string) error {
	t, err := getHtmlTemplate(constants.PasswordResetHtmlTemplatePath)
	if err != nil {
		ml.logger.Err(err).Msgf("Error during reading email template")
		return err
	}

	link := template.URL(fmt.Sprintf("%sreset-password/%s", ml.deepLinkUrl, key))

	data := struct {
		Link template.URL
		Name string
	}{
		Link: link,
		Name: name,
	}

	html, err := parseHtmlTemplate(t, data)

	ml.logger.Debug().Msgf("Sending password reset email to: %s", to)

	if err = ml.sendMail(Mail{
		Sender:   ml.username,
		To:       []string{to},
		Subject:  "CollectiHub - Password reset",
		BodyType: mail.TypeTextHTML,
		Body:     html,
	}); err != nil {
		ml.logger.Err(err).Msgf("Error during sending of mail")
	}

	return err
}

func (ml *Mailer) sendMail(mailObj Mail) error {
	m := mail.NewMsg()
	if err := m.From(ml.username); err != nil {
		return errors.New("error during setting email sender")
	}

	if err := m.To(mailObj.To...); err != nil {
		return errors.New("error during setting email recepient")
	}

	m.Subject(mailObj.Subject)
	m.SetBodyString(mailObj.BodyType, fmt.Sprintf(mailObj.Body))
	c, err := mail.NewClient(
		ml.host,
		mail.WithPort(ml.port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithTLSPortPolicy(mail.TLSMandatory),
		mail.WithUsername(ml.username),
		mail.WithPassword(ml.password),
	)
	if err != nil {
		return errors.New("error during email client creation")
	}

	if err := c.DialAndSend(m); err != nil {
		ml.logger.Error().Err(err).Msgf("Error happened during sending mail with %s:%d", ml.host, ml.port)
		return errors.New("error during sending mail")
	}

	return nil
}
