package main

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/kilo666mj/gatekit/approval"
	"github.com/kilo666mj/gatekit/store"
	"strings"
)

func approveWithScope(st *store.Store, fp, label, ranges string, unrestricted, register bool) error {
	if ranges != "" && unrestricted {
		return errors.New("--ranges and --unrestricted are mutually exclusive")
	}
	var scope *approval.Scope
	if !unrestricted {
		var err error
		scope, err = approval.New(strings.Split(ranges, ","))
		if err != nil {
			return err
		}
	}
	if register {
		method, err := st.GetMeta(metaFingerprintMethod)
		if err != nil {
			return err
		}
		if !validFingerprintForMethod(fp, FingerprintMethod(method)) {
			return fmt.Errorf("--register requires a full fingerprint")
		}
		if _, err := reconcileFingerprintFormat(st, false); err != nil {
			return err
		}
	}
	e, err := st.Get(fp)
	if err != nil && (!register || !errors.Is(err, sql.ErrNoRows)) {
		return err
	}
	if label == "" {
		label = e.Label
	}
	return st.ApplyDecisions([]store.Decision{{Fingerprint: fp, Status: StatusApproved, Label: label, ApprovalRanges: scope}}, "", "")
}
