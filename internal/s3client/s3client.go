package s3client

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Client struct {
	Client *s3.Client
}

func New() *S3Client {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		panic("unable to load AWS SDK config, " + err.Error())
	}

	client := s3.NewFromConfig(cfg)

	return &S3Client{
		Client: client,
	}
}

func (s *S3Client) GetUrlForUploadedFile(bucket_name string, region string, key string) string {
	return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket_name, region, key)
}
