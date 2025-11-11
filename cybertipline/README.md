# Cyber Tipline
Go client for reporting incidents to NCMEC's Cyber Tipline.

## Authentication
A username and password are required to authenticate with the Cyber Tipline API. Electronic service providers (ESPs)
can email **ESPteam [AT] ncmec.org** to start the application and vetting process or request more information.

## Installation
Add the package to your Go module using:

```bash
go get github.com/Boostport/ncmec-go
```
## Example
Here is a complete example of reporting an incident to the Cyber Tipline:

```go
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/Boostport/ncmec-go"
	"github.com/Boostport/ncmec-go/cybertipline"
)

func main() {
	client := cybertipline.NewClient("your-username", "your-password", cybertipline.Testing) // Uses the testing environment, replace with `Production` for live reports

	report := cybertipline.Report{
		IncidentSummary: &cybertipline.IncidentSummary{
			IncidentType:     cybertipline.IncidentTypeChildPornographyPossessionManufactureAndDistribution,
			IncidentDateTime: ncmec.Time(time.Now()),
		},
		Reporter: &cybertipline.Reporter{
			ReportingPerson: &cybertipline.Person{
				FirstName: ncmec.String("John"),
				LastName:  ncmec.String("Smith"),
			},
		},
	}

	reportID, err := client.Submit(context.Background(), report)
	if err != nil {
		log.Fatalf("Failed to submit report: %s", err)
	}

	root, err := os.OpenRoot(".")
	if err != nil {
		log.Fatalf("Failed to open root: %s", err)
	}
	defer root.Close()

	image, err := root.Open("some-image.jpg")
	if err != nil {
		log.Fatalf("Failed to open image: %s", err)
	}
	defer image.Close()

	fileID, err := client.Upload(context.Background(), reportID, "some-image.jpg", image)
	if err != nil {
		log.Fatalf("Failed to upload file: %s", err)
	}

	fileDetails := cybertipline.FileDetails{
		ReportId:         reportID,
		FileId:           fileID,
		FileName:         ncmec.String("some-image.jpg"),
		OriginalFileName: ncmec.String("original-image.jpg"),
	}

	err = client.FileInfo(context.Background(), fileDetails)
	if err != nil {
		log.Fatalf("Failed to submit file details: %s", err)
	}

	retractReport := false // Change to true to retract the report instead of finishing it

	if retractReport {
		err = client.Retract(context.Background(), reportID)
		if err != nil {
			log.Fatalf("Failed to retract report: %s", err)
		}
	} else {
		err = client.Finish(context.Background(), reportID)
		if err != nil {
			log.Fatalf("Failed to finish report: %s", err)
		}
	}
}
```

## Pointer Types
The types provided in this SDK use pointer fields to differentiate between zero values and missing values. To facilitate
the creation of pointer values, the `ncmec` package provides helper functions for converting types to their pointer
equivalents.

## Date Type
The SDK provides a custom `ncmec.Date` type for handling date fields in accordance with the Cyber Tipline API
specifications. This type can be converted from a `time.Time` using the `ncmec.DateFromTime()` function or created using
the `ncmec.NewDate()` function.

## Example Report and FileDetails
To see an example of a `Report` and `FileDetails` struct with all possible fields populated, refer to the
`TestClientMaximalReport` test in [`client_test.go`](client_test.go).

## Generate Types
To generate the SDK types from the Cyber Tipline XSD, export the `CYBER_TIPLINE_USERNAME` and `CYBER_TIPLINE_PASSWORD`
environment variables with your Cyber Tipline credentials, then run `go generate` in the `cybertipline` directory.

## Testing
To run integration tests against the Cyber Tipline testing environment, set the `CYBER_TIPLINE_USERNAME` and
`CYBER_TIPLINE_PASSWORD` environment variables with your Cyber Tipline testing credentials, then run `go test -v -race`.