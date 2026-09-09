package mobilecore

import "testing"

func TestSubscriptionRejectsInvalidCacheBodies(t *testing.T) {
	for _, body := range []string{"<html>maintenance</html>", "not a config", "proxies: [", "proxies: []", "rules: []"} {
		if _, err := ConvertSubscription(body); err == nil {
			t.Errorf("accepted invalid subscription %q", body)
		}
	}
}
