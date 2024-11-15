package main

import (
	"context"
	"fmt"
	"kadocore/internal/constants"
	"kadocore/internal/data"
	"kadocore/internal/util"
	"kadocore/internal/util/json"
	"kadocore/types"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// FileUpload godoc
//
//	@Summary		Upload file
//	@Description	Serves as route to upload file to uploading service (S3)
//	@Tags			file-upload
//	@Security		BearerAuth
//	@Produce		json
//	@Param			file	formData	file	false	"File to upload"
//	@Success		200		{object}	types.SuccessResponse{data=data.FileUploadResponse}
//	@Failure		400		{object}	types.ErrorResponse	"parsing/uploading error"
//	@Router			/file-upload [post]
func (app *application) uploadFile(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(200 << 20) // max size 200MB
	if err != nil {
		app.logger.Error().Err(err).Msg("FormData parsing error")
		json.ErrorJSON(w, constants.FormDataExceedsLimitErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
			Err:    err,
		})
		return
	}

	file, file_header, err := r.FormFile("file")
	if err != nil {
		app.logger.Error().Err(err).Msg("FormData file reading error")
		json.ErrorJSON(w, constants.FormDataDecodeErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
			Err:    err,
		})
		return
	}

	extParts := strings.Split(file_header.Filename, ".")

	if len(extParts) < 2 {
		app.logger.Error().Err(err).Msg("Filename reading error")
		json.ErrorJSON(w, constants.FormDataDecodeErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
			Err:    err,
		})
		return
	}

	ext := extParts[len(extParts)-1]
	filename := fmt.Sprintf("%s.%s", util.GenerateCleanUUID(), ext)

	_, err = app.s3client.Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(app.config.S3BucketName),
		Key:    aws.String(filename),
		Body:   file,
	})
	if err != nil {
		app.logger.Error().Err(err).Msg("File uploading error")
		json.ErrorJSON(w, constants.UploadingServiceErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
			Err:    err,
		})
		return
	}

	location := app.s3client.GetUrlForUploadedFile(app.config.S3BucketName, app.s3client.Client.Options().Region, filename)

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, &data.FileUploadResponse{
		Location: location,
	}, nil)
}
