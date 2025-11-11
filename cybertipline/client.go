//go:generate go run generate/generate.go

package cybertipline

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"time"
)

type Environment string

const (
	Production Environment = "https://report.cybertip.org/ispws"
	Testing    Environment = "https://exttest.cybertip.org/ispws"
)

type Client struct {
	username    string
	password    string
	environment Environment
	httpClient  *http.Client
}

func WithHTTPClient(httpClient *http.Client) func(*Client) {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

func NewClient(username string, password string, environment Environment, options ...func(client *Client)) *Client {
	client := &Client{
		username:    username,
		password:    password,
		environment: environment,
	}

	for _, option := range options {
		option(client)
	}

	if client.httpClient == nil {
		client.httpClient = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ForceAttemptHTTP2:     true,
				MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
			},
		}
	}

	return client
}

func (c *Client) Submit(ctx context.Context, report Report) (int64, error) {
	reportXML, err := xml.Marshal(report)
	if err != nil {
		return 0, fmt.Errorf("error mashaling report to XML: %w", err)
	}

	resp, err := c.post(ctx, "/submit", "text/xml; charset=utf-8", bytes.NewReader(reportXML))
	if err != nil {
		return 0, fmt.Errorf("error submitting report: %w", err)
	}
	defer resp.Body.Close()

	var reportResponse ReportResponse
	if err := xml.NewDecoder(resp.Body).Decode(&reportResponse); err != nil {
		return 0, fmt.Errorf("error decoding report response: %w", err)
	}

	if *reportResponse.ResponseCode != 0 {
		return 0, fmt.Errorf("error from server: %s", *reportResponse.ResponseDescription)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, errors.New(http.StatusText(resp.StatusCode))
	}

	return *reportResponse.ReportId, nil
}

func (c *Client) Upload(ctx context.Context, reportId int64, filename string, data io.Reader) (string, error) {
	buf := bytes.NewBuffer(nil)
	w := multipart.NewWriter(buf)

	err := w.WriteField("id", strconv.FormatInt(reportId, 10))
	if err != nil {
		return "", fmt.Errorf("error writing report ID field: %w", err)
	}

	fileWriter, err := w.CreateFormFile("file", filename)
	if err != nil {
		return "", fmt.Errorf("error creating form file: %w", err)
	}

	_, err = io.Copy(fileWriter, data)
	if err != nil {
		return "", fmt.Errorf("error copying file data: %w", err)
	}

	err = w.Close()
	if err != nil {
		return "", fmt.Errorf("error closing multipart writer: %w", err)
	}

	resp, err := c.post(ctx, "/upload", w.FormDataContentType(), buf)
	if err != nil {
		return "", fmt.Errorf("error uploading file: %w", err)
	}
	defer resp.Body.Close()

	var reportResponse ReportResponse
	if err := xml.NewDecoder(resp.Body).Decode(&reportResponse); err != nil {
		return "", fmt.Errorf("error decoding upload response: %w", err)
	}

	if *reportResponse.ResponseCode != 0 {
		return "", fmt.Errorf("error from server: %s", *reportResponse.ResponseDescription)
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(http.StatusText(resp.StatusCode))
	}

	return *reportResponse.FileId, nil
}

func (c *Client) FileInfo(ctx context.Context, details FileDetails) error {
	fileInfoXML, err := xml.Marshal(details)
	if err != nil {
		return fmt.Errorf("error marshaling file details to XML: %w", err)
	}

	resp, err := c.post(ctx, "/fileinfo", "text/xml; charset=utf-8", bytes.NewReader(fileInfoXML))
	if err != nil {
		return fmt.Errorf("error sending file info: %w", err)
	}
	defer resp.Body.Close()

	var reportResponse ReportResponse
	if err := xml.NewDecoder(resp.Body).Decode(&reportResponse); err != nil {
		return fmt.Errorf("error decoding file info response: %w", err)
	}

	if *reportResponse.ResponseCode != 0 {
		return fmt.Errorf("error from server: %s", *reportResponse.ResponseDescription)
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New(http.StatusText(resp.StatusCode))
	}

	return nil
}

func (c *Client) Finish(ctx context.Context, reportId int64) error {
	form := url.Values{}
	form.Set("id", strconv.FormatInt(int64(reportId), 10))

	resp, err := c.post(ctx, "/finish", "application/x-www-form-urlencoded", bytes.NewBufferString(form.Encode()))
	if err != nil {
		return fmt.Errorf("error finishing report: %w", err)
	}

	defer resp.Body.Close()

	var reportDoneResponse ReportDoneResponse
	if err := xml.NewDecoder(resp.Body).Decode(&reportDoneResponse); err != nil {
		return fmt.Errorf("error decoding finish response: %w", err)
	}

	if *reportDoneResponse.ResponseCode != 0 {
		return errors.New("error finishing report")
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New(http.StatusText(resp.StatusCode))
	}
	return nil
}

func (c *Client) Retract(ctx context.Context, reportId int64) error {
	form := url.Values{}
	form.Set("id", strconv.FormatInt(int64(reportId), 10))

	resp, err := c.post(ctx, "/retract", "application/x-www-form-urlencoded", bytes.NewBufferString(form.Encode()))
	if err != nil {
		return fmt.Errorf("error retracting report: %w", err)
	}

	defer resp.Body.Close()

	var reportResponse ReportResponse
	if err := xml.NewDecoder(resp.Body).Decode(&reportResponse); err != nil {
		return fmt.Errorf("error decoding finish response: %w", err)
	}

	if *reportResponse.ResponseCode != 0 {
		return errors.New("error retracting report")
	}
	return nil
}

func (c *Client) post(ctx context.Context, path string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", string(c.environment)+path, body)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", contentType)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}

	return resp, nil
}
