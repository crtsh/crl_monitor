/* crt.sh: crl_monitor - CRL Monitor
 * Written by Rob Stradling
 * Copyright (C) 2017-2020 Sectigo Limited
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
	"encoding/asn1"
	"flag"
	"fmt"
	"github.com/lib/pq"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

type config struct {
	// Common configuration parameters shared by all processors.
	ConnInfo string
	ConnOpen int
	ConnIdle int
	ConnLife duration
	Interval duration
	Batch int
	Concurrent int
	// Processor-specific config.
	Chunk int
	HTTPTimeout duration
}

type Work struct {
	c *config
	db *sql.DB
	transport http.Transport
	http_client http.Client
	create_temp_table_statement *sql.Stmt
	crl_update_statement *sql.Stmt
}

type WorkItem struct {
	work *Work
	ca_id int32
	distribution_point_url string
	crl_size sql.NullInt64
	this_update time.Time
	next_update time.Time
	issuer_cert []byte
	error_message sql.NullString
	crl_sha256 [sha256.Size]byte
	start_time time.Time
	already_updated bool
}


func checkRedirectURL(req *http.Request, via []*http.Request) error {
	// Fixup incorrectly encoded redirect URLs
	req.URL.RawQuery = strings.Replace(req.URL.RawQuery, " ", "%20", -1)
	return nil
}

// tomlConfig.DefineCustomFlags() and tomlConfig.PrintCustomFlags()
// Specify command-line flags that are specific to this processor.
func (c *config) DefineCustomFlags() {
	flag.DurationVar(&c.HTTPTimeout.Duration, "httptimeout", c.HTTPTimeout.Duration, "HTTP timeout")
}
func (c *config) PrintCustomFlags() string {
	return fmt.Sprintf("httptimeout:%s", c.HTTPTimeout.Duration)
}


func (w *Work) Init(c *config) {
	w.c = c
	w.transport = http.Transport { TLSClientConfig: &tls.Config { InsecureSkipVerify: true } }
	w.http_client = http.Client { CheckRedirect: checkRedirectURL, Timeout: c.HTTPTimeout.Duration, Transport: &w.transport }

	var err error

	w.create_temp_table_statement, err = w.db.Prepare(`
CREATE TEMP TABLE crl_revoked_import_temp (
	SERIAL_NUMBER bytea,
	REASON_CODE smallint,
	REVOCATION_DATE timestamp
) ON COMMIT DROP
`)
	checkErr(err)

	w.crl_update_statement, err = w.db.Prepare("SELECT crl_update($1,$2,$3,$4,$5,$6,$7,$8)")
	checkErr(err)
}

// Work.Begin
// Do any DB stuff that needs to happen before a batch of work.
func (w *Work) Begin(db *sql.DB) {
}

// Work.End
// Do any DB stuff that needs to happen after a batch of work.
func (w *Work) End() {
}

// Work.Exit
// One-time program exit code.
func (w *Work) Exit() {
	w.create_temp_table_statement.Close()
	w.crl_update_statement.Close()
}

// Work.Prepare()
// Prepare the driving SELECT query.
func (w *Work) SelectQuery(batch_size int) string {
	return fmt.Sprintf(`
SELECT crl.CA_ID, crl.DISTRIBUTION_POINT_URL, coalesce(crl.THIS_UPDATE, 'epoch'::timestamp), coalesce(crl.NEXT_UPDATE, 'epoch'::timestamp), coalesce(c2.CERTIFICATE, c1.CERTIFICATE)
	FROM crl
		LEFT JOIN LATERAL (
			SELECT c1.CERTIFICATE, c1.ISSUER_CA_ID
				FROM ca_certificate cac1, certificate c1
				WHERE crl.CA_ID = cac1.CA_ID
					AND cac1.CERTIFICATE_ID = c1.ID
				LIMIT 1
		) c1 ON TRUE
		LEFT JOIN LATERAL (
			SELECT c2.CERTIFICATE
				FROM ca_certificate cac2, certificate c2
				WHERE cac2.CA_ID = c1.ISSUER_CA_ID
					AND cac2.CERTIFICATE_ID = c2.ID
					AND EXISTS (SELECT 1 FROM x509_extKeyUsages(c1.CERTIFICATE) WHERE x509_extKeyUsages = '1.3.6.1.4.1.11129.2.4.4')
				LIMIT 1
		) c2 ON TRUE
	WHERE crl.IS_ACTIVE = 't'
		AND crl.NEXT_CHECK_DUE < now() AT TIME ZONE 'UTC'
	ORDER BY crl.IS_ACTIVE, crl.NEXT_CHECK_DUE
	LIMIT %d
`, batch_size)
}

// WorkItem.Parse()
// Parse one SELECTed row to configure one work item.
func (wi *WorkItem) Parse(rs *sql.Rows) error {
	return rs.Scan(&wi.ca_id, &wi.distribution_point_url, &wi.this_update, &wi.next_update, &wi.issuer_cert)
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
	wi.start_time = time.Now().UTC()
	wi.work = w
	wi.error_message.String = ""
	wi.error_message.Valid = false
	wi.crl_size.Valid = false
	wi.already_updated = false

	// Retrieve the CRL
	var err error
	var crl *pkix.CertificateList
	var body []byte
	if strings.HasPrefix(strings.ToLower(wi.distribution_point_url), "ldap") {
		// TODO: Support LDAP CRL URLs
		wi.error_message.String = "Unsupported URL scheme"
		wi.error_message.Valid = true
		log.Printf("%s: %s", wi.error_message.String, wi.distribution_point_url)
		return
	} else {
		// Fetch the CRL via HTTP(S)
		req, err := http.NewRequest("GET", wi.distribution_point_url, nil)
		wi.checkErr(err)
		req.Header.Add("User-Agent", "crt.sh")
		req.Header.Add("If-Modified-Since", wi.this_update.Format(http.TimeFormat))

		resp, err := w.http_client.Do(req)
		wi.checkErr(err)
		defer resp.Body.Close()
		if resp.StatusCode == 304 {
			log.Printf("Not Modified (304): %s", wi.distribution_point_url)
			return
		}
		if resp.StatusCode != 200 {
			wi.error_message.String = fmt.Sprintf("HTTP %d", resp.StatusCode)
			wi.error_message.Valid = true
			log.Printf("%s: %s", wi.error_message.String, wi.distribution_point_url)
			return
		}

		// Extract the HTTP response body
		body, err = ioutil.ReadAll(resp.Body)
		wi.checkErr(err)
	}

	// Progress report
	wi.crl_size.Int64 = int64(len(body))
	wi.crl_size.Valid = true
	log.Printf("Downloaded (%d bytes): %s", wi.crl_size.Int64, wi.distribution_point_url)

	// Calculate SHA-256(CRL)
	wi.crl_sha256 = sha256.Sum256(body)

	// Parse the CRL
	crl, err = x509.ParseCRL(body)
	if err != nil {
		log.Printf("x509.ParseCRL() => %v", err)
		wi.error_message.String = err.Error()
		wi.error_message.Valid = true
		return
	}

	// Extract various fields from this CRL
	var temp_this_update = wi.this_update
	wi.this_update = crl.TBSCertList.ThisUpdate
	wi.next_update = crl.TBSCertList.NextUpdate

	// Check that this CRL is newer than the last one we processed
	if temp_this_update.Sub(wi.this_update) >= 0 {
		log.Printf("Not Modified (thisUpdate): %s", wi.distribution_point_url)
		return
	}

	// Parse the supplied issuer certificate
	cert, err := x509.ParseCertificate(wi.issuer_cert)
	wi.checkErr(err)

	// Check this CRL's signature using the supplied issuer certificate
	err = cert.CheckCRLSignature(crl)
	if err != nil {
		log.Printf("cert.CheckCRLSignature() => %v", err)
		wi.error_message.String = err.Error()
		wi.error_message.Valid = true
		return
	}

	// Show progress report
	log.Printf("Verified: %s", wi.distribution_point_url)

	// TODO: Check crl.HasExpired(time.Now) ?
	// TODO: Set inactive if "latest" CRL is ancient?
	// TODO: Deactivate if duplicate of another CDP?

	// Begin a new transaction.
	tx, err := db.Begin()
	wi.checkErr(err)
	defer tx.Rollback()

	// Prepare some statements for this transaction.
	tx_create_temp_table_statement := tx.Stmt(w.create_temp_table_statement)
	defer tx_create_temp_table_statement.Close()
	tx_crl_update_statement := tx.Stmt(w.crl_update_statement)
	defer tx_crl_update_statement.Close()

	// Create the temporary "crl_revoked_import_temp" table.
	_, err = tx_create_temp_table_statement.Exec()
	wi.checkErr(err)

	if crl.TBSCertList.RevokedCertificates != nil {
		// Prepare the COPY statement.
		tx_copy_item_statement, err := tx.Prepare(pq.CopyIn("crl_revoked_import_temp", "serial_number", "reason_code", "revocation_date"))
		wi.checkErr(err)

		// Loop through the revoked certs, adding each one to the bulk import.
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

			// Get the bytes of the encoded serial number
			serial_bytes, err := asn1.Marshal(revoked_cert.SerialNumber)
			wi.checkErr(err)
			if serial_bytes[1] > 0x7F {
				log.Printf("Serial number has multiple length octets")
			} else {
				// The [2:] strips the ASN.1 tag and length octets.
				_, err = tx_copy_item_statement.Exec(serial_bytes[2:], reason_code, revoked_cert.RevocationTime)
				wi.checkErr(err)
			}
		}

		// Execute the COPY statement, to perform the bulk import.
		_, err = tx_copy_item_statement.Exec()
		wi.checkErr(err)
	}

	// Process the bulk-imported data.
	_, err = tx_crl_update_statement.Exec(wi.ca_id, wi.distribution_point_url, wi.this_update, wi.next_update, wi.start_time, wi.error_message, wi.crl_sha256[:], wi.crl_size)
	wi.checkErr(err)

	// Commit the transaction.  This will drop the temporary table.
	err = tx.Commit()
	wi.checkErr(err)

	log.Printf("Processed (%d revocations): %s (%v)", len(crl.TBSCertList.RevokedCertificates), wi.distribution_point_url, time.Now().UTC().Sub(wi.start_time))
	wi.already_updated = true
}

// Work.UpdateStatement()
// Prepare the UPDATE statement to be run when a CRL has not changed.
func (w *Work) UpdateStatement() string {
	return `
UPDATE crl
	SET LAST_CHECKED=statement_timestamp() AT TIME ZONE 'UTC',
		NEXT_CHECK_DUE=statement_timestamp() AT TIME ZONE 'UTC' + interval '4 hours',
		ERROR_MESSAGE=$1::text
	WHERE CA_ID=$2
		AND DISTRIBUTION_POINT_URL=$3
`
}

// WorkItem.Update()
// Update the DB with the results of the work for this item.
func (wi *WorkItem) Update(update_statement *sql.Stmt) (sql.Result, error) {
	if !wi.already_updated {
		return update_statement.Exec(wi.error_message, wi.ca_id, wi.distribution_point_url)
	} else {
		return nil, nil
	}
}
