/* crl_monitor - Certificate Revocation List Monitor
 * Written by Rob Stradling
 * Copyright (C) 2016-2017 COMODO CA Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

type Work struct {
	timeout time.Duration
	transport http.Transport
	http_client http.Client
	upsert_statement *sql.Stmt
	update_changed_crl_statement *sql.Stmt
}

type WorkItem struct {
	work *Work
	ca_id int32
	crl_url string
	crl_size sql.NullInt64
	this_update time.Time
	next_update time.Time
	last_checked time.Time
	issuer_cert []byte
	error_message sql.NullString
	crl_sha256 [sha256.Size]byte
	has_crl_changed bool
}

func checkRedirectURL(req *http.Request, via []*http.Request) error {
	// Fixup incorrectly encoded redirect URLs
	req.URL.RawQuery = strings.Replace(req.URL.RawQuery, " ", "%20", -1)
	return nil
}

func (w *Work) CustomFlags() string {
	flag.DurationVar(&w.timeout, "timeout", 15 * time.Second, "HTTP timeout")
	return fmt.Sprintf("  timeout: %s\n", w.timeout)
}

func (w *Work) Init() {
	w.transport = http.Transport { TLSClientConfig: &tls.Config { InsecureSkipVerify: true } }
	w.http_client = http.Client { CheckRedirect: checkRedirectURL, Timeout: w.timeout, Transport: &w.transport }
}

// Work.Begin
// Do any DB stuff that needs to happen before a batch of work.
func (w *Work) Begin(db *sql.DB) {
	var err error

	w.upsert_statement, err = db.Prepare(`
INSERT INTO crl_revoked (
	CA_ID, SERIAL_NUMBER, REASON_CODE,
	REVOCATION_DATE, LAST_SEEN_CHECK_DATE
)
VALUES (
	$1, decode($2, 'hex'), $3::smallint,
	$4,
	statement_timestamp()
)
ON CONFLICT ON CONSTRAINT crlr_pk
	DO UPDATE SET REASON_CODE = $3::smallint,
	REVOCATION_DATE = $4,
	LAST_SEEN_CHECK_DATE = statement_timestamp()
`)
	checkErr(err)

	w.update_changed_crl_statement, err = db.Prepare(`
UPDATE CRL
	SET CRL_SHA256=$1,
		THIS_UPDATE=$2::timestamp,
		NEXT_UPDATE=$3::timestamp,
		LAST_CHECKED=statement_timestamp(),
		NEXT_CHECK_DUE=statement_timestamp() + interval '1 hour',
		ERROR_MESSAGE=$4::text,
		CRL_SIZE=$5
	WHERE CA_ID=$6
		AND DISTRIBUTION_POINT_URL=$7
`)
	checkErr(err)
}

// Work.End
// Do any DB stuff that needs to happen after a batch of work.
func (w *Work) End() {
	w.upsert_statement.Close()
	w.update_changed_crl_statement.Close()
}

// Work.Prepare()
// Prepare the driving SELECT query.
func (w *Work) SelectQuery(batch_size int) string {
	return fmt.Sprintf(`
SELECT crl.CA_ID, crl.DISTRIBUTION_POINT_URL, coalesce(crl.THIS_UPDATE, 'epoch'::timestamp), coalesce(crl.NEXT_UPDATE, 'epoch'::timestamp), coalesce(crl.LAST_CHECKED, 'epoch'::timestamp), c.CERTIFICATE
	FROM crl LEFT JOIN LATERAL
		(SELECT c.CERTIFICATE
			FROM ca_certificate cac, certificate c
			WHERE crl.CA_ID = cac.CA_ID
				AND cac.CERTIFICATE_ID = c.ID
			LIMIT 1) c ON TRUE
	WHERE crl.IS_ACTIVE = 't'
		AND crl.NEXT_CHECK_DUE < statement_timestamp()
	ORDER BY crl.IS_ACTIVE, crl.NEXT_CHECK_DUE
	LIMIT %d
`, batch_size)
}

// WorkItem.Parse()
// Parse one SELECTed row to configure one work item.
func (wi *WorkItem) Parse(rs *sql.Rows) error {
	return rs.Scan(&wi.ca_id, &wi.crl_url, &wi.this_update, &wi.next_update, &wi.last_checked, &wi.issuer_cert)
}

func (wi *WorkItem) checkErr(err error) {
	if err != nil {
		wi.error_message.String = err.Error()
		wi.error_message.Valid = true
		panic(err)
	}
}

// WorkItem.Perform()
// Do the work for one item.
func (wi *WorkItem) Perform(db *sql.DB, w *Work) {
	wi.work = w
	wi.error_message.String = ""
	wi.error_message.Valid = false
	wi.has_crl_changed = false

	// Retrieve the CRL
	var err error
	var crl *pkix.CertificateList
	var body []byte
	if strings.HasPrefix(strings.ToLower(wi.crl_url), "ldap") {
		// TODO: Support LDAP CRL URLs
		wi.error_message.String = "Unsupported URL scheme"
		wi.error_message.Valid = true
		log.Printf("%s: %s", wi.error_message.String, wi.crl_url)
		return
	} else {
		// Fetch the CRL via HTTP(S)
		req, err := http.NewRequest("GET", wi.crl_url, nil)
		wi.checkErr(err)
		req.Header.Add("User-Agent", "crt.sh")
		req.Header.Add("If-Modified-Since", wi.this_update.Format(http.TimeFormat))

		resp, err := w.http_client.Do(req)
		wi.checkErr(err)
		defer resp.Body.Close()
		if resp.StatusCode == 304 {
			log.Printf("Not Modified (304): %s", wi.crl_url)
			return
		}
		if resp.StatusCode != 200 {
			wi.error_message.String = fmt.Sprintf("HTTP %d", resp.StatusCode)
			wi.error_message.Valid = true
			log.Printf("%s: %s", wi.error_message.String, wi.crl_url)
			return
		}

		// Extract the HTTP response body
		body, err = ioutil.ReadAll(resp.Body)
		wi.checkErr(err)
	}

	// Progress report
	wi.crl_size.Int64 = int64(len(body))
	wi.crl_size.Valid = true
	log.Printf("Downloaded (%d bytes): %s", wi.crl_size.Int64, wi.crl_url)

	// Calculate SHA-256(CRL)
	wi.crl_sha256 = sha256.Sum256(body)

	// Parse the CRL
	crl, err = x509.ParseCRL(body)
	wi.checkErr(err)

	// Extract various fields from this CRL
	var temp_this_update = wi.this_update
	wi.this_update = crl.TBSCertList.ThisUpdate
	wi.next_update = crl.TBSCertList.NextUpdate

	// Check that this CRL is newer than the last one we processed
	if temp_this_update.Sub(wi.this_update) >= 0 {
		log.Printf("Not Modified (thisUpdate): %s", wi.crl_url)
		return
	}

	wi.has_crl_changed = true

	// Parse the supplied issuer certificate
	cert, err := x509.ParseCertificate(wi.issuer_cert)
	checkErr(err)

	// Check this CRL's signature using the supplied issuer certificate
	err = cert.CheckCRLSignature(crl)
	wi.checkErr(err)

	// Show progress report
	log.Printf("Verified: %s", wi.crl_url)

	// TODO: Check crl.HasExpired(time.Now) ?
	// TODO: Set inactive if "latest" CRL is ancient?
	// TODO: Deactivate if duplicate of another CDP?

	// Begin a new transaction, prepare the UPSERT statement, and defer the COMMIT statement.
	tx, err := db.Begin()
	defer tx.Commit()
	stmt := tx.Stmt(w.upsert_statement)
	defer stmt.Close()

	// Loop through revoked certs, UPSERTing each one into the DB
	for _, revoked_cert := range crl.TBSCertList.RevokedCertificates {
		// Get the CRL Entry Reason Code (if specified)
		var reason_code sql.NullInt64
		reason_code.Valid = false
		for _, ext := range revoked_cert.Extensions {
			if ext.Id.Equal([]int{2, 5, 29, 21}) {
				if bytes.HasPrefix(ext.Value, []byte{10, 1}) {	// ENUMERATED, length=1
					reason_code.Int64 = int64(ext.Value[2])
					reason_code.Valid = true
				}
			}
		}

		// Convert the revoked serial number to a hex string
		var serial_string = fmt.Sprintf("%X", revoked_cert.SerialNumber)
		if revoked_cert.SerialNumber.Sign() >= 0 {
			if len(serial_string) % 2 != 0 {
				serial_string = "0" + serial_string
			} else if serial_string[0] >= 56 {	// 56 = "8" in ASCII
				serial_string = "00" + serial_string
			}
		} else {
			// TODO: Handle negative serial numbers properly
			log.Printf("NEGATIVE serial number: %X", revoked_cert.SerialNumber)
		}

		// UPSERT this CRL entry
		result, err := stmt.Exec(wi.ca_id, serial_string, reason_code, revoked_cert.RevocationTime)
		wi.checkErr(err)
		rows_affected, err := result.RowsAffected()
		wi.checkErr(err)
		if rows_affected != 1 {
			wi.checkErr(errors.New("UPSERT failed"))
		}
	}

	log.Printf("Processed (%d revocations): %s", len(crl.TBSCertList.RevokedCertificates), wi.crl_url)
}

// Work.UpdateStatement()
// Prepare the UPDATE statement to be run after processing each work item.
func (w *Work) UpdateStatement() string {
	return `
UPDATE crl
	SET LAST_CHECKED=statement_timestamp(),
		NEXT_CHECK_DUE=statement_timestamp() + interval '1 hour',
		ERROR_MESSAGE=$1::text
	WHERE CA_ID=$2
		AND DISTRIBUTION_POINT_URL=$3
`
}

// WorkItem.Update()
// Update the DB with the results of the work for this item.
func (wi *WorkItem) Update(update_statement *sql.Stmt) (sql.Result, error) {
	if wi.has_crl_changed {
		return wi.work.update_changed_crl_statement.Exec(wi.crl_sha256[:], wi.this_update, wi.next_update, wi.error_message, wi.crl_size, wi.ca_id, wi.crl_url)
	} else {
		return update_statement.Exec(wi.error_message, wi.ca_id, wi.crl_url)
	}
}
