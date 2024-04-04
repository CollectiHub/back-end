package mailer

import (
	"collectihub/internal/config"
	"errors"
	"fmt"

	"github.com/wneessen/go-mail"

	"github.com/rs/zerolog"
)

type Mailer struct {
	username string
	password string
	host     string
	port     int
	baseUrl  string
	logger   *zerolog.Logger
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
		username: cfg.MailerUsername,
		password: cfg.MailerPassword,
		host:     cfg.MailerSmtpHost,
		port:     cfg.MailerSmtpPort,
		logger:   l,
	}
}

func (ml *Mailer) SendAccountVerificationEmail(to string, code string) error {
	html := fmt.Sprintf("<p>Your verification code is: %s</p>", code)

	return ml.sendMail(Mail{
		Sender:   ml.username,
		To:       []string{to},
		Subject:  "CollectiHub - Account verification",
		BodyType: mail.TypeTextHTML,
		Body:     html,
	})
}

func (ml *Mailer) SendPasswordResetVerificationEmail(to string, code string) error {
	html := fmt.Sprintf("<p>Your verification code for password reset is: %s</p>", code)

	return ml.sendMail(Mail{
		Sender:   ml.username,
		To:       []string{to},
		Subject:  "CollectiHub - Password reset",
		BodyType: mail.TypeTextHTML,
		Body:     html,
	})
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
