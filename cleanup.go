package main

import (
	"errors"
	"fmt"
)

// closeError runs a cleanup function and labels its failure, so a close error
// that reaches a caller says which resource failed to close.
func closeError(context string, closeFn func() error) error {
	if err := closeFn(); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}

// closeWithError joins a cleanup failure onto a function's named error return
// without discarding the primary error.
func closeWithError(errp *error, context string, closeFn func() error) {
	*errp = errors.Join(*errp, closeError(context, closeFn))
}
