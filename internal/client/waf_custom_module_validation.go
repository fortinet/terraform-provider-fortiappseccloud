package client

import "fmt"

func validateReviewedEnum(label, value string, allowed ...string) error {
	for _, candidate := range allowed {
		if value == candidate {
			return nil
		}
	}
	return fmt.Errorf("decode %s: unsupported value %q", label, value)
}

func validateReviewedStringListEnum(label string, values []string, allowed ...string) error {
	for _, value := range values {
		if err := validateReviewedEnum(label, value, allowed...); err != nil {
			return err
		}
	}
	return nil
}
