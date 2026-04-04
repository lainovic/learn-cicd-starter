package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		expectedKey string
		expectedErr string
	}{
		{
			name:        "no authorization header",
			header:      "",
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:        "valid ApiKey header",
			header:      "ApiKey my-secret-key",
			expectedKey: "my-secret-key",
			expectedErr: "",
		},
		{
			name:        "malformed header - wrong scheme",
			header:      "Bearer my-secret-key",
			expectedKey: "",
			expectedErr: "malformed authorization header",
		},
		{
			name:        "malformed header - missing key value",
			header:      "ApiKey",
			expectedKey: "",
			expectedErr: "malformed authorization header",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.header != "" {
				headers.Set("Authorization", tc.header)
			}

			key, err := GetAPIKey(headers)

			if key != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, key)
			}

			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			if errMsg != tc.expectedErr {
				t.Errorf("expected error %q, got %q", tc.expectedErr, errMsg)
			}
		})
	}
}
