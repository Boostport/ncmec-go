package cybertipline

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Boostport/ncmec-go"
)

type testFile struct {
	path    string
	details FileDetails
}

type testReport struct {
	report Report
	files  []testFile
}

func TestClientMinimalReport(t *testing.T) {
	report := Report{
		IncidentSummary: &IncidentSummary{
			IncidentType:     IncidentTypeChildPornographyPossessionManufactureAndDistribution,
			IncidentDateTime: ncmec.Time(time.Now()),
		},
		Reporter: &Reporter{
			ReportingPerson: &Person{
				FirstName: ncmec.String("John"),
				LastName:  ncmec.String("Smith"),
			},
		},
	}

	testFiles := []testFile{
		{
			path:    "../testdata/gopher.png",
			details: FileDetails{},
		},
	}

	testClient(t, report, testFiles)
}

func TestClientMaximalReport(t *testing.T) {

	reportIDs := submitPriorReports(t, 2)

	report := Report{
		IncidentSummary: &IncidentSummary{
			IncidentType:           IncidentTypeMisleadingDomainName,
			Platform:               ncmec.String("Test Platform"),
			EscalateToHighPriority: ncmec.String("Please escalate"),
			ReportAnnotations: &ReportAnnotations{
				Sextortion:                 ncmec.Bool(true),
				CsamSolicitation:           ncmec.Bool(true),
				MinorToMinorInteraction:    ncmec.Bool(true),
				Spam:                       ncmec.Bool(true),
				SadisticOnlineExploitation: ncmec.Bool(true),
			},
			IncidentDateTime:            ncmec.Time(time.Now()),
			IncidentDateTimeDescription: ncmec.String("Approximately 2 hours ago"),
		},
		InternetDetails: []InternetDetails{
			{
				WebPageIncident: &WebPageIncident{
					Url:            []string{"bad1.example.com", "bad2.example.com"},
					AdditionalInfo: ncmec.String("Some additional info about the webpage incident"),
				},
			},
			{
				EmailIncident: &EmailIncident{
					EmailAddress: []Email{
						{
							Value:            ncmec.String("bad1@example.com"),
							Type:             EmailTypeHome,
							Verified:         ncmec.Bool(true),
							VerificationDate: ncmec.Time(time.Now()),
						},
						{
							Value:    ncmec.String("bad2@example.com"),
							Type:     EmailTypeWork,
							Verified: ncmec.Bool(false),
						},
					},
					Content:        ncmec.String("Test content"),
					AdditionalInfo: ncmec.String("Test additional info"),
				},
			},
			{
				NewsgroupIncident: &NewsgroupIncident{
					Name: ncmec.String("bad.newsgroup.example.com"),
					EmailAddress: []Email{
						{
							Value:            ncmec.String("bad1@example.com"),
							Type:             EmailTypeHome,
							Verified:         ncmec.Bool(true),
							VerificationDate: ncmec.Time(time.Now()),
						},
						{
							Value:    ncmec.String("bad2@example.com"),
							Type:     EmailTypeWork,
							Verified: ncmec.Bool(false),
						},
					},
					Content:        ncmec.String("Test content"),
					AdditionalInfo: ncmec.String("Test additional info"),
				},
			},
			{
				ChatImIncident: &ChatImIncident{
					ChatClient:     ncmec.String("Test Chat Client"),
					ChatRoomName:   ncmec.String("Test Chat Room"),
					Content:        ncmec.String("Test content"),
					AdditionalInfo: ncmec.String("Test additional info"),
				},
			},
			{
				OnlineGamingIncident: &OnlineGamingIncident{
					GameName:       ncmec.String("Test Game"),
					Console:        ncmec.String("Test Console"),
					Content:        ncmec.String("Test content"),
					AdditionalInfo: ncmec.String("Test additional info"),
				},
			},
			{
				CellPhoneIncident: &CellPhoneIncident{
					PhoneNumber: &Phone{
						Value:              ncmec.String("1234567890"),
						Type:               PhoneTypeMobile,
						Verified:           ncmec.Bool(true),
						VerificationDate:   ncmec.Time(time.Now()),
						CountryCallingCode: ncmec.String("+1"),
						Extension:          ncmec.String("123"),
					},
					Latitude:       ncmec.Float64(-123.456),
					Longitude:      ncmec.Float64(+123.456),
					AdditionalInfo: ncmec.String("Test additional info"),
				},
			},
			{
				NonInternetIncident: &NonInternetIncident{
					LocationName: ncmec.String("Test Location"),
					IncidentAddress: []Address{
						{
							Address: ncmec.String("123 Test St"),
							City:    ncmec.String("Test City"),
							ZipCode: ncmec.String("90001"),
							State:   StateCA,
							Country: CountryUS,
							Type:    AddressTypeHome,
						},
						{
							Address:     ncmec.String("123 Test St"),
							City:        ncmec.String("Test City"),
							ZipCode:     ncmec.String("90001"),
							NonUsaState: ncmec.String("Test State"),
							Country:     CountryAU,
							Type:        AddressTypeHome,
						},
					},
					AdditionalInfo: ncmec.String("Test additional info"),
				},
			},
			{
				Peer2peerIncident: &Peer2peerIncident{
					Client: ncmec.String("Test Client"),
					IpCaptureEvent: []IpCaptureEvent{
						{
							IpAddress:     ncmec.String("192.168.1.1"),
							EventName:     IpCaptureTypeUpload,
							DateTime:      ncmec.Time(time.Now()),
							PossibleProxy: ncmec.Bool(true),
							Port:          ncmec.Int(12345),
						},
						{
							IpAddress:     ncmec.String("192.168.1.2"),
							EventName:     IpCaptureTypeRegistration,
							DateTime:      ncmec.Time(time.Now()),
							PossibleProxy: ncmec.Bool(false),
							Port:          ncmec.Int(54321),
						},
					},
					FileNames:      ncmec.String("file.jpg"),
					AdditionalInfo: ncmec.String("Test additional info"),
				},
			},
		},
		LawEnforcement: &LawEnforcement{
			AgencyName: ncmec.String("Test Agency"),
			CaseNumber: ncmec.String("CASE 123456"),
			OfficerContact: &ContactPerson{
				FirstName: ncmec.String("Jane"),
				LastName:  ncmec.String("Officer"),
				Phone: []Phone{
					{
						Value:              ncmec.String("0987654321"),
						Type:               PhoneTypeWork,
						Verified:           ncmec.Bool(true),
						VerificationDate:   ncmec.Time(time.Now()),
						CountryCallingCode: ncmec.String("+1"),
						Extension:          ncmec.String("456"),
					},
					{
						Value:              ncmec.String("1122334455"),
						Type:               PhoneTypeMobile,
						Verified:           ncmec.Bool(false),
						CountryCallingCode: ncmec.String("+1"),
					},
				},
				Email: []Email{
					{
						Value:            ncmec.String("officer1@example.com"),
						Type:             EmailTypeWork,
						Verified:         ncmec.Bool(true),
						VerificationDate: ncmec.Time(time.Now()),
					},
					{
						Value:    ncmec.String("officer2@example.com"),
						Type:     EmailTypeBusiness,
						Verified: ncmec.Bool(false),
					},
				},
				Address: []Address{
					{
						Address: ncmec.String("456 Law St"),
						City:    ncmec.String("Law City"),
						ZipCode: ncmec.String("90002"),
						State:   StateNY,
						Country: CountryUS,
						Type:    AddressTypeBusiness,
					},
					{
						Address:     ncmec.String("789 Law St"),
						City:        ncmec.String("Law City"),
						ZipCode:     ncmec.String("90002"),
						NonUsaState: ncmec.String("Law State"),
						Country:     CountryCA,
						Type:        AddressTypeTechnical,
					},
				},
			},
			ReportedToLe:               ncmec.Bool(true),
			ServedLegalProcessDomestic: ncmec.Bool(true),
			ServedLegalProcessInternational: &ServedLegalProcessInternational{
				Value:       ncmec.Bool(true),
				FleaCountry: CountryAU,
			},
		},
		Reporter: &Reporter{
			ReportingPerson: &Person{
				FirstName: ncmec.String("Alice"),
				LastName:  ncmec.String("Reporter"),
				Phone: []Phone{
					{
						Value:              ncmec.String("5556667777"),
						Type:               PhoneTypeMobile,
						Verified:           ncmec.Bool(true),
						VerificationDate:   ncmec.Time(time.Now()),
						CountryCallingCode: ncmec.String("+1"),
					},
					{
						Value:              ncmec.String("8889990000"),
						Type:               PhoneTypeHome,
						CountryCallingCode: ncmec.String("+1"),
						Extension:          ncmec.String("456"),
					},
				},
				Email: []Email{
					{
						Value:            ncmec.String("reporter1@example.com"),
						Type:             EmailTypeWork,
						Verified:         ncmec.Bool(true),
						VerificationDate: ncmec.Time(time.Now()),
					},
					{
						Value:    ncmec.String("reporter2@example.com"),
						Type:     EmailTypeHome,
						Verified: ncmec.Bool(false),
					},
				},
				Address: []Address{
					{
						Address: ncmec.String("321 Company St"),
						City:    ncmec.String("Company City"),
						ZipCode: ncmec.String("90003"),
						State:   StateCA,
						Country: CountryUS,
						Type:    AddressTypeBusiness,
					},
					{
						Address:     ncmec.String("654 Company St"),
						City:        ncmec.String("Company City"),
						ZipCode:     ncmec.String("90003"),
						NonUsaState: ncmec.String("Company State"),
						Country:     CountryGB,
						Type:        AddressTypeTechnical,
					},
				},
			},
			ContactPerson: &ContactPerson{
				FirstName: ncmec.String("Bob"),
				LastName:  ncmec.String("Contact"),
				Phone: []Phone{
					{
						Value:              ncmec.String("5556667777"),
						Type:               PhoneTypeMobile,
						Verified:           ncmec.Bool(true),
						VerificationDate:   ncmec.Time(time.Now()),
						CountryCallingCode: ncmec.String("+1"),
					},
					{
						Value:              ncmec.String("8889990000"),
						Type:               PhoneTypeHome,
						CountryCallingCode: ncmec.String("+1"),
						Extension:          ncmec.String("456"),
					},
				},
				Email: []Email{
					{
						Value:            ncmec.String("reporter1@example.com"),
						Type:             EmailTypeWork,
						Verified:         ncmec.Bool(true),
						VerificationDate: ncmec.Time(time.Now()),
					},
					{
						Value:    ncmec.String("reporter2@example.com"),
						Type:     EmailTypeHome,
						Verified: ncmec.Bool(false),
					},
				},
				Address: []Address{
					{
						Address: ncmec.String("321 Company St"),
						City:    ncmec.String("Company City"),
						ZipCode: ncmec.String("90003"),
						State:   StateCA,
						Country: CountryUS,
						Type:    AddressTypeBusiness,
					},
					{
						Address:     ncmec.String("654 Company St"),
						City:        ncmec.String("Company City"),
						ZipCode:     ncmec.String("90003"),
						NonUsaState: ncmec.String("Company State"),
						Country:     CountryGB,
						Type:        AddressTypeTechnical,
					},
				},
			},
			CompanyTemplate: ncmec.String("Test template"),
			TermsOfService:  ncmec.String("Test terms of service"),
			LegalURL:        ncmec.String("https://www.example.com/legal"),
		},
		PersonOrUserReported: &PersonOrUserReported{
			PersonOrUserReportedPerson: &Person{
				FirstName: ncmec.String("Charlie"),
				LastName:  ncmec.String("Reported"),
				Phone: []Phone{
					{
						Value:              ncmec.String("1112223333"),
						Type:               PhoneTypeMobile,
						Verified:           ncmec.Bool(true),
						VerificationDate:   ncmec.Time(time.Now()),
						CountryCallingCode: ncmec.String("+1"),
					},
					{
						Value:              ncmec.String("4445556666"),
						Type:               PhoneTypeHome,
						CountryCallingCode: ncmec.String("+1"),
						Extension:          ncmec.String("789"),
					},
				},
				Email: []Email{
					{
						Value:            ncmec.String("reportedperson1@example.com"),
						Type:             EmailTypeWork,
						Verified:         ncmec.Bool(true),
						VerificationDate: ncmec.Time(time.Now()),
					},
					{
						Value:    ncmec.String("bad2@example.com"),
						Type:     EmailTypeHome,
						Verified: ncmec.Bool(false),
					},
				},
				Address: []Address{
					{
						Address: ncmec.String("987 Reported St"),
						City:    ncmec.String("Reported City"),
						ZipCode: ncmec.String("90004"),
						State:   StateTX,
						Country: CountryUS,
						Type:    AddressTypeHome,
					},
					{
						Address:     ncmec.String("654 Reported St"),
						City:        ncmec.String("Reported City"),
						ZipCode:     ncmec.String("90004"),
						NonUsaState: ncmec.String("Reported State"),
						Country:     CountryFR,
						Type:        AddressTypeHome,
					},
				},
				Age:         ncmec.Int(25),
				DateOfBirth: ncmec.NewDate(2000, 01, 01),
			},
			VehicleDescription: ncmec.String("Test vehicle description"),
			EspIdentifier:      ncmec.String("Test EspIdentifier"),
			EspService:         ncmec.String("Test EspService"),
			CompromisedAccount: ncmec.Bool(true),
			ScreenName:         ncmec.String("Test screenName"),
			DisplayName: []string{
				"Display Name 1",
				"Display Name 2",
			},
			ProfileUrl: []string{
				"https://profile1.example.com",
				"https://profile2.example.com",
			},
			ProfileBio: ncmec.String("Test profile bio"),
			IpCaptureEvent: []IpCaptureEvent{
				{
					IpAddress:     ncmec.String("192.168.1.1"),
					EventName:     IpCaptureTypeLogin,
					DateTime:      ncmec.Time(time.Now()),
					PossibleProxy: ncmec.Bool(true),
					Port:          ncmec.Int(12345),
				},
				{
					IpAddress:     ncmec.String("192.168.1.2"),
					EventName:     IpCaptureTypeRegistration,
					DateTime:      ncmec.Time(time.Now()),
					PossibleProxy: ncmec.Bool(false),
					Port:          ncmec.Int(54321),
				},
			},
			DeviceId: []DeviceId{
				{
					IdType:    ncmec.String("IMEI"),
					IdValue:   ncmec.String("123456789012345"),
					EventName: IpCaptureTypeUpload,
					DateTime:  ncmec.Time(time.Now()),
				},
				{
					IdType:    ncmec.String("SSID"),
					IdValue:   ncmec.String("123456789012345"),
					EventName: IpCaptureTypePurchase,
					DateTime:  ncmec.Time(time.Now()),
				},
			},
			PriorCTReports:  reportIDs,
			GroupIdentifier: ncmec.String("Test GroupIdentifier"),
			AccountTemporarilyDisabled: &AccountTemporarilyDisabled{
				Value:            ncmec.Bool(true),
				DisabledDate:     ncmec.Time(time.Now()),
				UserNotified:     ncmec.Bool(true),
				UserNotifiedDate: ncmec.Time(time.Now()),
				ReenabledDate:    ncmec.Time(time.Now().Add(48 * time.Hour)),
			},
			AccountPermanentlyDisabled: &AccountPermanentlyDisabled{
				Value:            ncmec.Bool(true),
				DisabledDate:     ncmec.Time(time.Now()),
				UserNotified:     ncmec.Bool(true),
				UserNotifiedDate: ncmec.Time(time.Now()),
			},
			EstimatedLocation: &EstimatedLocation{
				City:        ncmec.String("Estimated City"),
				Region:      StateCA.StringPtr(),
				CountryCode: CountryUS,
				Verified:    ncmec.Bool(true),
				Timestamp:   ncmec.Time(time.Now()),
			},
			AllEmailsReported: ncmec.Bool(true),
			AdditionalInfo:    ncmec.String("Test additional info"),
		},
		IntendedRecipient: []IntendedRecipient{
			{
				IntendedRecipientPerson: &Person{
					FirstName: ncmec.String("Diana"),
					LastName:  ncmec.String("Recipient"),
					Phone: []Phone{
						{
							Value:              ncmec.String("7778889999"),
							Type:               PhoneTypeMobile,
							Verified:           ncmec.Bool(true),
							VerificationDate:   ncmec.Time(time.Now()),
							CountryCallingCode: ncmec.String("+1"),
						},
						{
							Value:              ncmec.String("0001112222"),
							Type:               PhoneTypeHome,
							Verified:           ncmec.Bool(false),
							CountryCallingCode: ncmec.String("+1"),
							Extension:          ncmec.String("321"),
						},
					},
					Email: []Email{
						{
							Value:            ncmec.String("bad1@example.com"),
							Type:             EmailTypeWork,
							Verified:         ncmec.Bool(true),
							VerificationDate: ncmec.Time(time.Now()),
						},
						{
							Value:    ncmec.String("intendedrecepient2@example.com"),
							Type:     EmailTypeHome,
							Verified: ncmec.Bool(false),
						},
					},
					Address: []Address{
						{
							Address: ncmec.String("159 Recipient St"),
							City:    ncmec.String("Recipient City"),
							ZipCode: ncmec.String("90005"),
							State:   StateFL,
							Country: CountryUS,
							Type:    AddressTypeHome,
						},
						{
							Address:     ncmec.String("753 Recipient St"),
							City:        ncmec.String("Recipient City"),
							ZipCode:     ncmec.String("90005"),
							NonUsaState: ncmec.String("Recipient State"),
							Country:     CountryDE,
							Type:        AddressTypeHome,
						},
					},
					Age:         ncmec.Int(30),
					DateOfBirth: ncmec.NewDate(2000, 02, 01),
				},
				EspIdentifier:      ncmec.String("Test Esp Identifier"),
				EspService:         ncmec.String("Test Esp Service"),
				CompromisedAccount: ncmec.Bool(true),
				ScreenName:         ncmec.String("Test Screen Name"),
				DisplayName: []string{
					"Display Name A",
					"Display Name B",
				},
				ProfileUrl: []string{
					"https://profileA.example.com",
					"https://profileB.example.com",
				},
				ProfileBio: ncmec.String("Test profile bio for intended recipient"),
				IpCaptureEvent: []IpCaptureEvent{
					{
						IpAddress:     ncmec.String("192.168.1.1"),
						EventName:     IpCaptureTypeLogin,
						DateTime:      ncmec.Time(time.Now()),
						PossibleProxy: ncmec.Bool(true),
						Port:          ncmec.Int(12345),
					},
					{
						IpAddress:     ncmec.String("192.168.1.2"),
						EventName:     IpCaptureTypeRegistration,
						DateTime:      ncmec.Time(time.Now()),
						PossibleProxy: ncmec.Bool(false),
						Port:          ncmec.Int(54321),
					},
				},
				DeviceId: []DeviceId{
					{
						IdType:    ncmec.String("IMEI"),
						IdValue:   ncmec.String("123456789012345"),
						EventName: IpCaptureTypeUpload,
						DateTime:  ncmec.Time(time.Now()),
					},
					{
						IdType:    ncmec.String("SSID"),
						IdValue:   ncmec.String("123456789012345"),
						EventName: IpCaptureTypePurchase,
						DateTime:  ncmec.Time(time.Now()),
					},
				},
				PriorCTReports:  reportIDs,
				GroupIdentifier: ncmec.String("Test GroupIdentifier"),
				AccountTemporarilyDisabled: &AccountTemporarilyDisabled{
					Value:            ncmec.Bool(true),
					DisabledDate:     ncmec.Time(time.Now()),
					UserNotified:     ncmec.Bool(true),
					UserNotifiedDate: ncmec.Time(time.Now()),
					ReenabledDate:    ncmec.Time(time.Now().Add(48 * time.Hour)),
				},
				AccountPermanentlyDisabled: &AccountPermanentlyDisabled{
					Value:            ncmec.Bool(true),
					DisabledDate:     ncmec.Time(time.Now()),
					UserNotified:     ncmec.Bool(true),
					UserNotifiedDate: ncmec.Time(time.Now()),
				},
				EstimatedLocation: &EstimatedLocation{
					City:        ncmec.String("Estimated City"),
					Region:      StateCA.StringPtr(),
					CountryCode: CountryUS,
					Verified:    ncmec.Bool(true),
					Timestamp:   ncmec.Time(time.Now()),
				},
				AllEmailsReported: ncmec.Bool(true),
				AdditionalInfo: []string{
					"Test additional info A",
					"Test additional info B",
				},
			},
			{
				IntendedRecipientPerson: &Person{
					FirstName: ncmec.String("David"),
					LastName:  ncmec.String("Recipient"),
					Phone: []Phone{
						{
							Value:              ncmec.String("7778889999"),
							Type:               PhoneTypeMobile,
							Verified:           ncmec.Bool(true),
							VerificationDate:   ncmec.Time(time.Now()),
							CountryCallingCode: ncmec.String("+1"),
						},
						{
							Value:              ncmec.String("0001112222"),
							Type:               PhoneTypeHome,
							Verified:           ncmec.Bool(false),
							CountryCallingCode: ncmec.String("+1"),
							Extension:          ncmec.String("321"),
						},
					},
					Email: []Email{
						{
							Value:            ncmec.String("intendedrecipient1@example.com"),
							Type:             EmailTypeWork,
							Verified:         ncmec.Bool(true),
							VerificationDate: ncmec.Time(time.Now()),
						},
						{
							Value:    ncmec.String("intendedrecepient2@example.com"),
							Type:     EmailTypeHome,
							Verified: ncmec.Bool(false),
						},
					},
					Address: []Address{
						{
							Address: ncmec.String("159 Recipient St"),
							City:    ncmec.String("Recipient City"),
							ZipCode: ncmec.String("90005"),
							State:   StateFL,
							Country: CountryUS,
							Type:    AddressTypeHome,
						},
						{
							Address:     ncmec.String("753 Recipient St"),
							City:        ncmec.String("Recipient City"),
							ZipCode:     ncmec.String("90005"),
							NonUsaState: ncmec.String("Recipient State"),
							Country:     CountryDE,
							Type:        AddressTypeHome,
						},
					},
					Age:         ncmec.Int(30),
					DateOfBirth: ncmec.NewDate(2000, 02, 01),
				},
				EspIdentifier:      ncmec.String("Test Esp Identifier"),
				EspService:         ncmec.String("Test Esp Service"),
				CompromisedAccount: ncmec.Bool(true),
				ScreenName:         ncmec.String("Test Screen Name"),
				DisplayName: []string{
					"Display Name A",
					"Display Name B",
				},
				ProfileUrl: []string{
					"https://profileA.example.com",
					"https://profileB.example.com",
				},
				ProfileBio: ncmec.String("Test profile bio for intended recipient"),
				IpCaptureEvent: []IpCaptureEvent{
					{
						IpAddress:     ncmec.String("192.168.1.1"),
						EventName:     IpCaptureTypeLogin,
						DateTime:      ncmec.Time(time.Now()),
						PossibleProxy: ncmec.Bool(true),
						Port:          ncmec.Int(12345),
					},
					{
						IpAddress:     ncmec.String("192.168.1.2"),
						EventName:     IpCaptureTypeRegistration,
						DateTime:      ncmec.Time(time.Now()),
						PossibleProxy: ncmec.Bool(false),
						Port:          ncmec.Int(54321),
					},
				},
				DeviceId: []DeviceId{
					{
						IdType:    ncmec.String("IMEI"),
						IdValue:   ncmec.String("123456789012345"),
						EventName: IpCaptureTypeUpload,
						DateTime:  ncmec.Time(time.Now()),
					},
					{
						IdType:    ncmec.String("SSID"),
						IdValue:   ncmec.String("123456789012345"),
						EventName: IpCaptureTypePurchase,
						DateTime:  ncmec.Time(time.Now()),
					},
				},
				PriorCTReports:  reportIDs,
				GroupIdentifier: ncmec.String("Test GroupIdentifier"),
				AccountTemporarilyDisabled: &AccountTemporarilyDisabled{
					Value:            ncmec.Bool(true),
					DisabledDate:     ncmec.Time(time.Now()),
					UserNotified:     ncmec.Bool(true),
					UserNotifiedDate: ncmec.Time(time.Now()),
					ReenabledDate:    ncmec.Time(time.Now().Add(48 * time.Hour)),
				},
				AccountPermanentlyDisabled: &AccountPermanentlyDisabled{
					Value:            ncmec.Bool(true),
					DisabledDate:     ncmec.Time(time.Now()),
					UserNotified:     ncmec.Bool(true),
					UserNotifiedDate: ncmec.Time(time.Now()),
				},
				EstimatedLocation: &EstimatedLocation{
					City:        ncmec.String("Estimated City"),
					Region:      StateCA.StringPtr(),
					CountryCode: CountryUS,
					Verified:    ncmec.Bool(true),
					Timestamp:   ncmec.Time(time.Now()),
				},
				AllEmailsReported: ncmec.Bool(true),
				AdditionalInfo: []string{
					"Test additional info A",
					"Test additional info B",
				},
			},
		},
		Victim: []Victim{
			{
				VictimPerson: &Person{
					FirstName: ncmec.String("Victor"),
					LastName:  ncmec.String("Victim"),
					Phone: []Phone{
						{
							Value:              ncmec.String("2223334444"),
							Type:               PhoneTypeMobile,
							Verified:           ncmec.Bool(true),
							VerificationDate:   ncmec.Time(time.Now()),
							CountryCallingCode: ncmec.String("+1"),
						},
						{
							Value:              ncmec.String("5556667777"),
							Type:               PhoneTypeHome,
							CountryCallingCode: ncmec.String("+1"),
							Extension:          ncmec.String("654"),
						},
					},
					Email: []Email{
						{
							Value:            ncmec.String("victim1@example.com"),
							Type:             EmailTypeWork,
							Verified:         ncmec.Bool(true),
							VerificationDate: ncmec.Time(time.Now()),
						},
						{
							Value:    ncmec.String("victim2@example.com"),
							Type:     EmailTypeHome,
							Verified: ncmec.Bool(false),
						},
					},
					Address: []Address{
						{
							Address: ncmec.String("258 Victim St"),
							City:    ncmec.String("Victim City"),
							ZipCode: ncmec.String("90006"),
							State:   StateIL,
							Country: CountryUS,
							Type:    AddressTypeHome,
						},
						{
							Address:     ncmec.String("147 Victim St"),
							City:        ncmec.String("Victim City"),
							ZipCode:     ncmec.String("90006"),
							NonUsaState: ncmec.String("Victim State"),
							Country:     CountryIT,
							Type:        AddressTypeHome,
						},
					},
					Age:         ncmec.Int(15),
					DateOfBirth: ncmec.NewDate(2010, 03, 01),
				},
				EspIdentifier:      ncmec.String("Test Esp Identifier"),
				EspService:         ncmec.String("Test Esp Service"),
				CompromisedAccount: ncmec.Bool(true),
				ScreenName:         ncmec.String("Test Screen Name"),
				DisplayName: []string{
					"Display Name X",
					"Display Name Y",
				},
				ProfileUrl: []string{
					"https://profileX.example.com",
					"https://profileY.example.com",
				},
				ProfileBio: ncmec.String("Test profile bio for victim"),
				IpCaptureEvent: []IpCaptureEvent{
					{
						IpAddress:     ncmec.String("10.0.0.2"),
						EventName:     IpCaptureTypeLogin,
						DateTime:      ncmec.Time(time.Now()),
						PossibleProxy: ncmec.Bool(true),
						Port:          ncmec.Int(23456),
					},
					{
						IpAddress:     ncmec.String("10.0.0.3"),
						EventName:     IpCaptureTypeRegistration,
						DateTime:      ncmec.Time(time.Now()),
						PossibleProxy: ncmec.Bool(false),
						Port:          ncmec.Int(65432),
					},
				},
				DeviceId: []DeviceId{
					{
						IdType:    ncmec.String("IMEI"),
						IdValue:   ncmec.String("543210987654321"),
						EventName: IpCaptureTypeUpload,
						DateTime:  ncmec.Time(time.Now()),
					},
					{
						IdType:    ncmec.String("SSID"),
						IdValue:   ncmec.String("543210987654321"),
						EventName: IpCaptureTypePurchase,
						DateTime:  ncmec.Time(time.Now()),
					},
				},
				SchoolName:     ncmec.String("Test School"),
				PriorCTReports: reportIDs,
				AccountTemporarilyDisabled: &AccountTemporarilyDisabled{
					Value:            ncmec.Bool(true),
					DisabledDate:     ncmec.Time(time.Now()),
					UserNotified:     ncmec.Bool(true),
					UserNotifiedDate: ncmec.Time(time.Now()),
					ReenabledDate:    ncmec.Time(time.Now().Add(48 * time.Hour)),
				},
				AccountPermanentlyDisabled: &AccountPermanentlyDisabled{
					Value:            ncmec.Bool(true),
					DisabledDate:     ncmec.Time(time.Now()),
					UserNotified:     ncmec.Bool(true),
					UserNotifiedDate: ncmec.Time(time.Now()),
				},
				EstimatedLocation: &EstimatedLocation{
					City:        ncmec.String("Estimated City"),
					Region:      StateCA.StringPtr(),
					CountryCode: CountryUS,
					Verified:    ncmec.Bool(true),
					Timestamp:   ncmec.Time(time.Now()),
				},
				AllEmailsReported: ncmec.Bool(true),
				AssociatedAccount: []AssociatedAccount{
					{
						Platform: &Platform{
							Value:          ncmec.String("Test Platform"),
							ThirdPartyUser: ncmec.Bool(true),
						},
						FirstName:      ncmec.String("John"),
						MiddleName:     ncmec.String("William"),
						LastName:       ncmec.String("Victim"),
						ApproximateAge: ncmec.Int(15),
						DateOfBirth:    ncmec.NewDate(2010, 03, 01),
						Phone: []Phone{
							{
								Value:              ncmec.String("2223334444"),
								Type:               PhoneTypeMobile,
								Verified:           ncmec.Bool(true),
								VerificationDate:   ncmec.Time(time.Now()),
								CountryCallingCode: ncmec.String("+1"),
							},
							{
								Value:              ncmec.String("5556667777"),
								Type:               PhoneTypeHome,
								CountryCallingCode: ncmec.String("+1"),
								Extension:          ncmec.String("654"),
							},
						},
						Email: []Email{
							{
								Value:            ncmec.String("victim1@example.com"),
								Type:             EmailTypeWork,
								Verified:         ncmec.Bool(true),
								VerificationDate: ncmec.Time(time.Now()),
							},
							{
								Value:    ncmec.String("victim2@example.com"),
								Type:     EmailTypeHome,
								Verified: ncmec.Bool(false),
							},
						},
						AllEmailsReported: ncmec.Bool(true),
						Address: []Address{
							{
								Address: ncmec.String("258 Victim St"),
								City:    ncmec.String("Victim City"),
								ZipCode: ncmec.String("90006"),
								State:   StateIL,
								Country: CountryUS,
								Type:    AddressTypeHome,
							},
							{
								Address:     ncmec.String("147 Victim St"),
								City:        ncmec.String("Victim City"),
								ZipCode:     ncmec.String("90006"),
								NonUsaState: ncmec.String("Victim State"),
								Country:     CountryIT,
								Type:        AddressTypeHome,
							},
						},
						EspService:    ncmec.String("Test Esp Service"),
						EspIdentifier: ncmec.String("Test Esp Identifier"),
						ProfileUrl: []string{
							"https://associatedprofile1.example.com",
							"https://associatedprofile2.example.com",
						},
						ScreenName: ncmec.String("Test Screen Name"),
						DisplayName: []string{
							"Associated Display Name 1",
							"Associated Display Name 2",
						},
						ProfileBio:         ncmec.String("Test profile bio for associated account"),
						GroupIdentifier:    ncmec.String("Test Group Identifier"),
						CompromisedAccount: ncmec.Bool(true),
						AccountTemporarilyDisabled: &AccountTemporarilyDisabled{
							Value:            ncmec.Bool(true),
							DisabledDate:     ncmec.Time(time.Now()),
							UserNotified:     ncmec.Bool(true),
							UserNotifiedDate: ncmec.Time(time.Now()),
							ReenabledDate:    ncmec.Time(time.Now().Add(48 * time.Hour)),
						},
						AccountPermanentlyDisabled: &AccountPermanentlyDisabled{
							Value:            ncmec.Bool(true),
							DisabledDate:     ncmec.Time(time.Now()),
							UserNotified:     ncmec.Bool(true),
							UserNotifiedDate: ncmec.Time(time.Now()),
						},
						IpCaptureEvent: []IpCaptureEvent{
							{
								IpAddress:     ncmec.String("10.0.0.2"),
								EventName:     IpCaptureTypeLogin,
								DateTime:      ncmec.Time(time.Now()),
								PossibleProxy: ncmec.Bool(true),
								Port:          ncmec.Int(23456),
							},
							{
								IpAddress:     ncmec.String("10.0.0.3"),
								EventName:     IpCaptureTypeRegistration,
								DateTime:      ncmec.Time(time.Now()),
								PossibleProxy: ncmec.Bool(false),
								Port:          ncmec.Int(65432),
							},
						},
						DeviceId: []DeviceId{
							{
								IdType:    ncmec.String("IMEI"),
								IdValue:   ncmec.String("543210987654321"),
								EventName: IpCaptureTypeUpload,
								DateTime:  ncmec.Time(time.Now()),
							},
							{
								IdType:    ncmec.String("SSID"),
								IdValue:   ncmec.String("543210987654321"),
								EventName: IpCaptureTypePurchase,
								DateTime:  ncmec.Time(time.Now()),
							},
						},
						PriorCTReport:  reportIDs,
						AdditionalInfo: ncmec.String("Test Additional Info"),
						Type:           AssociatedAccountTypeCreator,
					},
					{
						Platform: &Platform{
							Value:          ncmec.String("Test Platform"),
							ThirdPartyUser: ncmec.Bool(true),
						},
						FirstName:      ncmec.String("John"),
						MiddleName:     ncmec.String("William"),
						LastName:       ncmec.String("Victim"),
						ApproximateAge: ncmec.Int(15),
						DateOfBirth:    ncmec.NewDate(2010, 03, 01),
						Phone: []Phone{
							{
								Value:              ncmec.String("2223334444"),
								Type:               PhoneTypeMobile,
								Verified:           ncmec.Bool(true),
								VerificationDate:   ncmec.Time(time.Now()),
								CountryCallingCode: ncmec.String("+1"),
							},
							{
								Value:              ncmec.String("5556667777"),
								Type:               PhoneTypeHome,
								CountryCallingCode: ncmec.String("+1"),
								Extension:          ncmec.String("654"),
							},
						},
						Email: []Email{
							{
								Value:            ncmec.String("victim1@example.com"),
								Type:             EmailTypeWork,
								Verified:         ncmec.Bool(true),
								VerificationDate: ncmec.Time(time.Now()),
							},
							{
								Value:    ncmec.String("victim2@example.com"),
								Type:     EmailTypeHome,
								Verified: ncmec.Bool(false),
							},
						},
						AllEmailsReported: ncmec.Bool(true),
						Address: []Address{
							{
								Address: ncmec.String("258 Victim St"),
								City:    ncmec.String("Victim City"),
								ZipCode: ncmec.String("90006"),
								State:   StateIL,
								Country: CountryUS,
								Type:    AddressTypeHome,
							},
							{
								Address:     ncmec.String("147 Victim St"),
								City:        ncmec.String("Victim City"),
								ZipCode:     ncmec.String("90006"),
								NonUsaState: ncmec.String("Victim State"),
								Country:     CountryIT,
								Type:        AddressTypeHome,
							},
						},
						EspService:    ncmec.String("Test Esp Service"),
						EspIdentifier: ncmec.String("Test Esp Identifier"),
						ProfileUrl: []string{
							"https://associatedprofile1.example.com",
							"https://associatedprofile2.example.com",
						},
						ScreenName: ncmec.String("Test Screen Name"),
						DisplayName: []string{
							"Associated Display Name 1",
							"Associated Display Name 2",
						},
						ProfileBio:         ncmec.String("Test profile bio for associated account"),
						GroupIdentifier:    ncmec.String("Test Group Identifier"),
						CompromisedAccount: ncmec.Bool(true),
						AccountTemporarilyDisabled: &AccountTemporarilyDisabled{
							Value:            ncmec.Bool(true),
							DisabledDate:     ncmec.Time(time.Now()),
							UserNotified:     ncmec.Bool(true),
							UserNotifiedDate: ncmec.Time(time.Now()),
							ReenabledDate:    ncmec.Time(time.Now().Add(48 * time.Hour)),
						},
						AccountPermanentlyDisabled: &AccountPermanentlyDisabled{
							Value:            ncmec.Bool(true),
							DisabledDate:     ncmec.Time(time.Now()),
							UserNotified:     ncmec.Bool(true),
							UserNotifiedDate: ncmec.Time(time.Now()),
						},
						IpCaptureEvent: []IpCaptureEvent{
							{
								IpAddress:     ncmec.String("10.0.0.2"),
								EventName:     IpCaptureTypeLogin,
								DateTime:      ncmec.Time(time.Now()),
								PossibleProxy: ncmec.Bool(true),
								Port:          ncmec.Int(23456),
							},
							{
								IpAddress:     ncmec.String("10.0.0.3"),
								EventName:     IpCaptureTypeRegistration,
								DateTime:      ncmec.Time(time.Now()),
								PossibleProxy: ncmec.Bool(false),
								Port:          ncmec.Int(65432),
							},
						},
						DeviceId: []DeviceId{
							{
								IdType:    ncmec.String("IMEI"),
								IdValue:   ncmec.String("543210987654321"),
								EventName: IpCaptureTypeUpload,
								DateTime:  ncmec.Time(time.Now()),
							},
							{
								IdType:    ncmec.String("SSID"),
								IdValue:   ncmec.String("543210987654321"),
								EventName: IpCaptureTypePurchase,
								DateTime:  ncmec.Time(time.Now()),
							},
						},
						PriorCTReport:  reportIDs,
						AdditionalInfo: ncmec.String("Test Additional Info"),
						Type:           AssociatedAccountTypeCreator,
					},
				},
				AdditionalInfo: ncmec.String("Test Additional Info"),
			},
			{
				VictimPerson: &Person{
					FirstName: ncmec.String("William"),
					LastName:  ncmec.String("Victim"),
					Phone: []Phone{
						{
							Value:              ncmec.String("2223334444"),
							Type:               PhoneTypeMobile,
							Verified:           ncmec.Bool(true),
							VerificationDate:   ncmec.Time(time.Now()),
							CountryCallingCode: ncmec.String("+1"),
						},
						{
							Value:              ncmec.String("5556667777"),
							Type:               PhoneTypeHome,
							CountryCallingCode: ncmec.String("+1"),
							Extension:          ncmec.String("654"),
						},
					},
					Email: []Email{
						{
							Value:            ncmec.String("victim1@example.com"),
							Type:             EmailTypeWork,
							Verified:         ncmec.Bool(true),
							VerificationDate: ncmec.Time(time.Now()),
						},
						{
							Value:    ncmec.String("victim2@example.com"),
							Type:     EmailTypeHome,
							Verified: ncmec.Bool(false),
						},
					},
					Address: []Address{
						{
							Address: ncmec.String("258 Victim St"),
							City:    ncmec.String("Victim City"),
							ZipCode: ncmec.String("90006"),
							State:   StateIL,
							Country: CountryUS,
							Type:    AddressTypeHome,
						},
						{
							Address:     ncmec.String("147 Victim St"),
							City:        ncmec.String("Victim City"),
							ZipCode:     ncmec.String("90006"),
							NonUsaState: ncmec.String("Victim State"),
							Country:     CountryIT,
							Type:        AddressTypeHome,
						},
					},
					Age:         ncmec.Int(15),
					DateOfBirth: ncmec.NewDate(2010, 03, 01),
				},
				EspIdentifier:      ncmec.String("Test Esp Identifier"),
				EspService:         ncmec.String("Test Esp Service"),
				CompromisedAccount: ncmec.Bool(true),
				ScreenName:         ncmec.String("Test Screen Name"),
				DisplayName: []string{
					"Display Name X",
					"Display Name Y",
				},
				ProfileUrl: []string{
					"https://profileX.example.com",
					"https://profileY.example.com",
				},
				ProfileBio: ncmec.String("Test profile bio for victim"),
				IpCaptureEvent: []IpCaptureEvent{
					{
						IpAddress:     ncmec.String("10.0.0.2"),
						EventName:     IpCaptureTypeLogin,
						DateTime:      ncmec.Time(time.Now()),
						PossibleProxy: ncmec.Bool(true),
						Port:          ncmec.Int(23456),
					},
					{
						IpAddress:     ncmec.String("10.0.0.3"),
						EventName:     IpCaptureTypeRegistration,
						DateTime:      ncmec.Time(time.Now()),
						PossibleProxy: ncmec.Bool(false),
						Port:          ncmec.Int(65432),
					},
				},
				DeviceId: []DeviceId{
					{
						IdType:    ncmec.String("IMEI"),
						IdValue:   ncmec.String("543210987654321"),
						EventName: IpCaptureTypeUpload,
						DateTime:  ncmec.Time(time.Now()),
					},
					{
						IdType:    ncmec.String("SSID"),
						IdValue:   ncmec.String("543210987654321"),
						EventName: IpCaptureTypePurchase,
						DateTime:  ncmec.Time(time.Now()),
					},
				},
				SchoolName:     ncmec.String("Test School"),
				PriorCTReports: reportIDs,
				AccountTemporarilyDisabled: &AccountTemporarilyDisabled{
					Value:            ncmec.Bool(true),
					DisabledDate:     ncmec.Time(time.Now()),
					UserNotified:     ncmec.Bool(true),
					UserNotifiedDate: ncmec.Time(time.Now()),
					ReenabledDate:    ncmec.Time(time.Now().Add(48 * time.Hour)),
				},
				AccountPermanentlyDisabled: &AccountPermanentlyDisabled{
					Value:            ncmec.Bool(true),
					DisabledDate:     ncmec.Time(time.Now()),
					UserNotified:     ncmec.Bool(true),
					UserNotifiedDate: ncmec.Time(time.Now()),
				},
				EstimatedLocation: &EstimatedLocation{
					City:        ncmec.String("Estimated City"),
					Region:      StateCA.StringPtr(),
					CountryCode: CountryUS,
					Verified:    ncmec.Bool(true),
					Timestamp:   ncmec.Time(time.Now()),
				},
				AllEmailsReported: ncmec.Bool(true),
				AssociatedAccount: []AssociatedAccount{
					{
						Platform: &Platform{
							Value:          ncmec.String("Test Platform"),
							ThirdPartyUser: ncmec.Bool(true),
						},
						FirstName:      ncmec.String("John"),
						MiddleName:     ncmec.String("William"),
						LastName:       ncmec.String("Victim"),
						ApproximateAge: ncmec.Int(15),
						DateOfBirth:    ncmec.NewDate(2010, 03, 01),
						Phone: []Phone{
							{
								Value:              ncmec.String("2223334444"),
								Type:               PhoneTypeMobile,
								Verified:           ncmec.Bool(true),
								VerificationDate:   ncmec.Time(time.Now()),
								CountryCallingCode: ncmec.String("+1"),
							},
							{
								Value:              ncmec.String("5556667777"),
								Type:               PhoneTypeHome,
								CountryCallingCode: ncmec.String("+1"),
								Extension:          ncmec.String("654"),
							},
						},
						Email: []Email{
							{
								Value:            ncmec.String("victim3@example.com"),
								Type:             EmailTypeWork,
								Verified:         ncmec.Bool(true),
								VerificationDate: ncmec.Time(time.Now()),
							},
							{
								Value:    ncmec.String("victim4@example.com"),
								Type:     EmailTypeHome,
								Verified: ncmec.Bool(false),
							},
						},
						AllEmailsReported: ncmec.Bool(true),
						Address: []Address{
							{
								Address: ncmec.String("258 Victim St"),
								City:    ncmec.String("Victim City"),
								ZipCode: ncmec.String("90006"),
								State:   StateIL,
								Country: CountryUS,
								Type:    AddressTypeHome,
							},
							{
								Address:     ncmec.String("147 Victim St"),
								City:        ncmec.String("Victim City"),
								ZipCode:     ncmec.String("90006"),
								NonUsaState: ncmec.String("Victim State"),
								Country:     CountryIT,
								Type:        AddressTypeHome,
							},
						},
						EspService:    ncmec.String("Test Esp Service"),
						EspIdentifier: ncmec.String("Test Esp Identifier"),
						ProfileUrl: []string{
							"https://associatedprofile1.example.com",
							"https://associatedprofile2.example.com",
						},
						ScreenName: ncmec.String("Test Screen Name"),
						DisplayName: []string{
							"Associated Display Name 1",
							"Associated Display Name 2",
						},
						ProfileBio:         ncmec.String("Test profile bio for associated account"),
						GroupIdentifier:    ncmec.String("Test Group Identifier"),
						CompromisedAccount: ncmec.Bool(true),
						AccountTemporarilyDisabled: &AccountTemporarilyDisabled{
							Value:            ncmec.Bool(true),
							DisabledDate:     ncmec.Time(time.Now()),
							UserNotified:     ncmec.Bool(true),
							UserNotifiedDate: ncmec.Time(time.Now()),
							ReenabledDate:    ncmec.Time(time.Now().Add(48 * time.Hour)),
						},
						AccountPermanentlyDisabled: &AccountPermanentlyDisabled{
							Value:            ncmec.Bool(true),
							DisabledDate:     ncmec.Time(time.Now()),
							UserNotified:     ncmec.Bool(true),
							UserNotifiedDate: ncmec.Time(time.Now()),
						},
						IpCaptureEvent: []IpCaptureEvent{
							{
								IpAddress:     ncmec.String("10.0.0.2"),
								EventName:     IpCaptureTypeLogin,
								DateTime:      ncmec.Time(time.Now()),
								PossibleProxy: ncmec.Bool(true),
								Port:          ncmec.Int(23456),
							},
							{
								IpAddress:     ncmec.String("10.0.0.3"),
								EventName:     IpCaptureTypeRegistration,
								DateTime:      ncmec.Time(time.Now()),
								PossibleProxy: ncmec.Bool(false),
								Port:          ncmec.Int(65432),
							},
						},
						DeviceId: []DeviceId{
							{
								IdType:    ncmec.String("IMEI"),
								IdValue:   ncmec.String("543210987654321"),
								EventName: IpCaptureTypeUpload,
								DateTime:  ncmec.Time(time.Now()),
							},
							{
								IdType:    ncmec.String("SSID"),
								IdValue:   ncmec.String("543210987654321"),
								EventName: IpCaptureTypePurchase,
								DateTime:  ncmec.Time(time.Now()),
							},
						},
						PriorCTReport:  reportIDs,
						AdditionalInfo: ncmec.String("Test Additional Info"),
						Type:           AssociatedAccountTypeCreator,
					},
					{
						Platform: &Platform{
							Value:          ncmec.String("Test Platform"),
							ThirdPartyUser: ncmec.Bool(true),
						},
						FirstName:      ncmec.String("John"),
						MiddleName:     ncmec.String("William"),
						LastName:       ncmec.String("Victim"),
						ApproximateAge: ncmec.Int(15),
						DateOfBirth:    ncmec.NewDate(2010, 03, 01),
						Phone: []Phone{
							{
								Value:              ncmec.String("2223334444"),
								Type:               PhoneTypeMobile,
								Verified:           ncmec.Bool(true),
								VerificationDate:   ncmec.Time(time.Now()),
								CountryCallingCode: ncmec.String("+1"),
							},
							{
								Value:              ncmec.String("5556667777"),
								Type:               PhoneTypeHome,
								CountryCallingCode: ncmec.String("+1"),
								Extension:          ncmec.String("654"),
							},
						},
						Email: []Email{
							{
								Value:            ncmec.String("victim1@example.com"),
								Type:             EmailTypeWork,
								Verified:         ncmec.Bool(true),
								VerificationDate: ncmec.Time(time.Now()),
							},
							{
								Value:    ncmec.String("victim2@example.com"),
								Type:     EmailTypeHome,
								Verified: ncmec.Bool(false),
							},
						},
						AllEmailsReported: ncmec.Bool(true),
						Address: []Address{
							{
								Address: ncmec.String("258 Victim St"),
								City:    ncmec.String("Victim City"),
								ZipCode: ncmec.String("90006"),
								State:   StateIL,
								Country: CountryUS,
								Type:    AddressTypeHome,
							},
							{
								Address:     ncmec.String("147 Victim St"),
								City:        ncmec.String("Victim City"),
								ZipCode:     ncmec.String("90006"),
								NonUsaState: ncmec.String("Victim State"),
								Country:     CountryIT,
								Type:        AddressTypeHome,
							},
						},
						EspService:    ncmec.String("Test Esp Service"),
						EspIdentifier: ncmec.String("Test Esp Identifier"),
						ProfileUrl: []string{
							"https://associatedprofile1.example.com",
							"https://associatedprofile2.example.com",
						},
						ScreenName: ncmec.String("Test Screen Name"),
						DisplayName: []string{
							"Associated Display Name 1",
							"Associated Display Name 2",
						},
						ProfileBio:         ncmec.String("Test profile bio for associated account"),
						GroupIdentifier:    ncmec.String("Test Group Identifier"),
						CompromisedAccount: ncmec.Bool(true),
						AccountTemporarilyDisabled: &AccountTemporarilyDisabled{
							Value:            ncmec.Bool(true),
							DisabledDate:     ncmec.Time(time.Now()),
							UserNotified:     ncmec.Bool(true),
							UserNotifiedDate: ncmec.Time(time.Now()),
							ReenabledDate:    ncmec.Time(time.Now().Add(48 * time.Hour)),
						},
						AccountPermanentlyDisabled: &AccountPermanentlyDisabled{
							Value:            ncmec.Bool(true),
							DisabledDate:     ncmec.Time(time.Now()),
							UserNotified:     ncmec.Bool(true),
							UserNotifiedDate: ncmec.Time(time.Now()),
						},
						IpCaptureEvent: []IpCaptureEvent{
							{
								IpAddress:     ncmec.String("10.0.0.2"),
								EventName:     IpCaptureTypeLogin,
								DateTime:      ncmec.Time(time.Now()),
								PossibleProxy: ncmec.Bool(true),
								Port:          ncmec.Int(23456),
							},
							{
								IpAddress:     ncmec.String("10.0.0.3"),
								EventName:     IpCaptureTypeRegistration,
								DateTime:      ncmec.Time(time.Now()),
								PossibleProxy: ncmec.Bool(false),
								Port:          ncmec.Int(65432),
							},
						},
						DeviceId: []DeviceId{
							{
								IdType:    ncmec.String("IMEI"),
								IdValue:   ncmec.String("543210987654321"),
								EventName: IpCaptureTypeUpload,
								DateTime:  ncmec.Time(time.Now()),
							},
							{
								IdType:    ncmec.String("SSID"),
								IdValue:   ncmec.String("543210987654321"),
								EventName: IpCaptureTypePurchase,
								DateTime:  ncmec.Time(time.Now()),
							},
						},
						PriorCTReport:  reportIDs,
						AdditionalInfo: ncmec.String("Test Additional Info"),
						Type:           AssociatedAccountTypeCreator,
					},
				},
				AdditionalInfo: ncmec.String("Test Additional Info"),
			},
		},
		AdditionalInfo: ncmec.String("Test Additional Info"),
	}

	testFiles := []testFile{
		{
			path: "../testdata/gopher.png",
			details: FileDetails{
				FileName:               ncmec.String("gopher.png"),
				OriginalFileName:       ncmec.String("gopher1.png"),
				UploadedToEspTimestamp: ncmec.Time(time.Now()),
				LocationOfFile:         ncmec.String("https://example.com/gopher1.png"),
				FileViewedByEsp:        ncmec.Bool(true),
				ExifViewedByEsp:        ncmec.Bool(true),
				PubliclyAvailable:      ncmec.Bool(true),
				FileRelevance:          FileRelevanceReported,
				IndustryClassification: FileClassificationA1,
				OriginalFileHash: []Hash{
					{
						HashType: ncmec.String("MD5"),
						Value:    ncmec.String("d41d8cd98f00b204e9800998ecf8427e"),
					},
					{
						HashType: ncmec.String("SHA256"),
						Value:    ncmec.String("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
					},
				},
				IpCaptureEvent: &IpCaptureEvent{
					IpAddress:     ncmec.String("10.0.0.2"),
					EventName:     IpCaptureTypeLogin,
					DateTime:      ncmec.Time(time.Now()),
					PossibleProxy: ncmec.Bool(true),
					Port:          ncmec.Int(23456),
				},
				DeviceId: []DeviceId{
					{
						IdType:    ncmec.String("IMEI"),
						IdValue:   ncmec.String("543210987654321"),
						EventName: IpCaptureTypeUpload,
						DateTime:  ncmec.Time(time.Now()),
					},
					{
						IdType:    ncmec.String("SSID"),
						IdValue:   ncmec.String("543210987654321"),
						EventName: IpCaptureTypePurchase,
						DateTime:  ncmec.Time(time.Now()),
					},
				},
				Details: []Details{
					{
						NameValuePair: []NameValue{
							{
								Name:  ncmec.String("Detail Name 1"),
								Value: ncmec.String("Detail Value 1"),
							},
							{
								Name:  ncmec.String("Detail Name 2"),
								Value: ncmec.String("Detail Value 2"),
							},
						},
					},
					{
						NameValuePair: []NameValue{
							{
								Name:  ncmec.String("Detail Name 1"),
								Value: ncmec.String("Detail Value 1"),
							},
							{
								Name:  ncmec.String("Detail Name 2"),
								Value: ncmec.String("Detail Value 2"),
							},
						},
					},
				},
				AdditionalInfo: []string{
					"Test file additional info A",
					"Test file additional info B",
				},
				FileAnnotations: &FileAnnotations{
					AnimeDrawingVirtualHentai: ncmec.Bool(true),
					PotentialMeme:             ncmec.Bool(true),
					Viral:                     ncmec.Bool(true),
					PossibleSelfProduction:    ncmec.Bool(true),
					PhysicalHarm:              ncmec.Bool(true),
					ViolenceGore:              ncmec.Bool(true),
					Bestiality:                ncmec.Bool(true),
					LiveStreaming:             ncmec.Bool(true),
					Infant:                    ncmec.Bool(true),
					GenerativeAi:              ncmec.Bool(true),
				},
			},
		},
		{
			path: "../testdata/gopher.png",
			details: FileDetails{
				FileName:               ncmec.String("gopher.png"),
				OriginalFileName:       ncmec.String("gopher1.png"),
				UploadedToEspTimestamp: ncmec.Time(time.Now()),
				LocationOfFile:         ncmec.String("https://example.com/gopher1.png"),
				FileViewedByEsp:        ncmec.Bool(true),
				ExifViewedByEsp:        ncmec.Bool(true),
				PubliclyAvailable:      ncmec.Bool(true),
				FileRelevance:          FileRelevanceReported,
				IndustryClassification: FileClassificationA1,
				OriginalFileHash: []Hash{
					{
						HashType: ncmec.String("MD5"),
						Value:    ncmec.String("d41d8cd98f00b204e9800998ecf8427e"),
					},
					{
						HashType: ncmec.String("SHA256"),
						Value:    ncmec.String("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
					},
				},
				IpCaptureEvent: &IpCaptureEvent{
					IpAddress:     ncmec.String("10.0.0.2"),
					EventName:     IpCaptureTypeLogin,
					DateTime:      ncmec.Time(time.Now()),
					PossibleProxy: ncmec.Bool(true),
					Port:          ncmec.Int(23456),
				},
				DeviceId: []DeviceId{
					{
						IdType:    ncmec.String("IMEI"),
						IdValue:   ncmec.String("543210987654321"),
						EventName: IpCaptureTypeUpload,
						DateTime:  ncmec.Time(time.Now()),
					},
					{
						IdType:    ncmec.String("SSID"),
						IdValue:   ncmec.String("543210987654321"),
						EventName: IpCaptureTypePurchase,
						DateTime:  ncmec.Time(time.Now()),
					},
				},
				Details: []Details{
					{
						NameValuePair: []NameValue{
							{
								Name:  ncmec.String("Detail Name 1"),
								Value: ncmec.String("Detail Value 1"),
							},
							{
								Name:  ncmec.String("Detail Name 2"),
								Value: ncmec.String("Detail Value 2"),
							},
						},
					},
					{
						NameValuePair: []NameValue{
							{
								Name:  ncmec.String("Detail Name 1"),
								Value: ncmec.String("Detail Value 1"),
							},
							{
								Name:  ncmec.String("Detail Name 2"),
								Value: ncmec.String("Detail Value 2"),
							},
						},
					},
				},
				AdditionalInfo: []string{
					"Test file additional info A",
					"Test file additional info B",
				},
				PotentialMeme: ncmec.Bool(true),
			},
		},
		{
			path: "../testdata/gopher.png",
			details: FileDetails{
				FileName:               ncmec.String("gopher.png"),
				OriginalFileName:       ncmec.String("gopher1.png"),
				UploadedToEspTimestamp: ncmec.Time(time.Now()),
				LocationOfFile:         ncmec.String("https://example.com/gopher1.png"),
				FileViewedByEsp:        ncmec.Bool(true),
				ExifViewedByEsp:        ncmec.Bool(true),
				PubliclyAvailable:      ncmec.Bool(true),
				FileRelevance:          FileRelevanceReported,
				IndustryClassification: FileClassificationA1,
				OriginalFileHash: []Hash{
					{
						HashType: ncmec.String("MD5"),
						Value:    ncmec.String("d41d8cd98f00b204e9800998ecf8427e"),
					},
					{
						HashType: ncmec.String("SHA256"),
						Value:    ncmec.String("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
					},
				},
				IpCaptureEvent: &IpCaptureEvent{
					IpAddress:     ncmec.String("10.0.0.2"),
					EventName:     IpCaptureTypeLogin,
					DateTime:      ncmec.Time(time.Now()),
					PossibleProxy: ncmec.Bool(true),
					Port:          ncmec.Int(23456),
				},
				DeviceId: []DeviceId{
					{
						IdType:    ncmec.String("IMEI"),
						IdValue:   ncmec.String("543210987654321"),
						EventName: IpCaptureTypeUpload,
						DateTime:  ncmec.Time(time.Now()),
					},
					{
						IdType:    ncmec.String("SSID"),
						IdValue:   ncmec.String("543210987654321"),
						EventName: IpCaptureTypePurchase,
						DateTime:  ncmec.Time(time.Now()),
					},
				},
				Details: []Details{
					{
						NameValuePair: []NameValue{
							{
								Name:  ncmec.String("Detail Name 1"),
								Value: ncmec.String("Detail Value 1"),
							},
							{
								Name:  ncmec.String("Detail Name 2"),
								Value: ncmec.String("Detail Value 2"),
							},
						},
					},
					{
						NameValuePair: []NameValue{
							{
								Name:  ncmec.String("Detail Name 1"),
								Value: ncmec.String("Detail Value 1"),
							},
							{
								Name:  ncmec.String("Detail Name 2"),
								Value: ncmec.String("Detail Value 2"),
							},
						},
					},
				},
				AdditionalInfo: []string{
					"Test file additional info A",
					"Test file additional info B",
				},
				FileAnnotations: &FileAnnotations{
					AnimeDrawingVirtualHentai: ncmec.Bool(true),
					PotentialMeme:             ncmec.Bool(true),
					Viral:                     ncmec.Bool(true),
					PossibleSelfProduction:    ncmec.Bool(true),
					PhysicalHarm:              ncmec.Bool(true),
					ViolenceGore:              ncmec.Bool(true),
					Bestiality:                ncmec.Bool(true),
					LiveStreaming:             ncmec.Bool(true),
					Infant:                    ncmec.Bool(true),
					GenerativeAi:              ncmec.Bool(true),
				},
			},
		},
	}

	testClient(t, report, testFiles)
}

func TestClientBatchedReport(t *testing.T) {
	report := Report{
		BatchedReport: &BatchedReport{
			Reason: BatchedReportReasonViralPotentialMeme,
		},
		IncidentSummary: &IncidentSummary{
			IncidentType:     IncidentTypeChildPornographyPossessionManufactureAndDistribution,
			IncidentDateTime: ncmec.Time(time.Now()),
		},
		Reporter: &Reporter{
			ReportingPerson: &Person{
				FirstName: ncmec.String("John"),
				LastName:  ncmec.String("Smith"),
			},
		},
	}

	testFiles := []testFile{
		{
			path: "../testdata/gopher.png",
			details: FileDetails{
				FileRelevance: FileRelevanceReported,
				FileAnnotations: &FileAnnotations{
					PotentialMeme: ncmec.Bool(true),
				},
			},
		},
	}

	testClient(t, report, testFiles)
}

func TestRetractReport(t *testing.T) {
	username, password := skipIfUsernamePasswordNotSet(t)

	client := NewClient(username, password, Testing)

	report := Report{
		BatchedReport: &BatchedReport{
			Reason: BatchedReportReasonViralPotentialMeme,
		},
		IncidentSummary: &IncidentSummary{
			IncidentType:     IncidentTypeChildPornographyPossessionManufactureAndDistribution,
			IncidentDateTime: ncmec.Time(time.Now()),
		},
		Reporter: &Reporter{
			ReportingPerson: &Person{
				FirstName: ncmec.String("John"),
				LastName:  ncmec.String("Smith"),
			},
		},
	}

	reportID, err := client.Submit(context.Background(), report)
	if err != nil {
		t.Fatalf("Failed to submit report: %v", err)
	}

	err = client.Retract(context.Background(), reportID)
	if err != nil {
		t.Fatalf("Failed to retract report: %v", err)
	}
}

func testClient(t *testing.T, report Report, files []testFile) {
	username, password := skipIfUsernamePasswordNotSet(t)

	client := NewClient(username, password, Testing)

	reportID, err := client.Submit(context.Background(), report)
	if err != nil {
		t.Fatalf("Failed to submit report: %v", err)
	}

	for _, file := range files {
		func(file testFile) {
			image, err := os.Open(file.path)
			if err != nil {
				t.Fatalf("Failed to open test image: %v", err)
			}
			defer image.Close()

			fileID, err := client.Upload(context.Background(), reportID, filepath.Base(file.path), image)
			if err != nil {
				t.Fatalf("Failed to upload file: %v", err)
			}

			fileDetails := file.details
			fileDetails.ReportId = ncmec.Int64(reportID)
			fileDetails.FileId = ncmec.String(fileID)

			err = client.FileInfo(context.Background(), fileDetails)
			if err != nil {
				t.Fatalf("Failed to submit file info: %v", err)
			}

		}(file)
	}

	err = client.Finish(context.Background(), reportID)
	if err != nil {
		t.Fatalf("Failed to finish report: %v", err)
	}

}

func submitPriorReports(t *testing.T, numReports int) []int64 {
	username, password := skipIfUsernamePasswordNotSet(t)
	client := NewClient(username, password, Testing)

	var priorReportIDs []int64

	report := Report{
		IncidentSummary: &IncidentSummary{
			IncidentType:     IncidentTypeChildPornographyPossessionManufactureAndDistribution,
			IncidentDateTime: ncmec.Time(time.Now()),
		},
		Reporter: &Reporter{
			ReportingPerson: &Person{
				FirstName: ncmec.String("John"),
				LastName:  ncmec.String("Smith"),
			},
		},
	}

	for i := 0; i < numReports; i++ {
		reportID, err := client.Submit(context.Background(), report)
		if err != nil {
			t.Fatalf("Failed to submit prior report: %v", err)
		}
		priorReportIDs = append(priorReportIDs, reportID)

		err = client.Finish(context.Background(), reportID)
		if err != nil {
			t.Fatalf("Failed to finish prior report: %v", err)
		}
	}

	return priorReportIDs
}

func skipIfUsernamePasswordNotSet(t *testing.T) (string, string) {
	username := os.Getenv("CYBER_TIPLINE_USERNAME")
	password := os.Getenv("CYBER_TIPLINE_PASSWORD")

	if username == "" || password == "" {
		t.Skip("Skipping test; CYBER_TIPLINE_USERNAME or CYBER_TIPLINE_PASSWORD environment variable not set")
	}

	return username, password
}
