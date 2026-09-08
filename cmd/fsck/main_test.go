// Copyright 2025 The Tessera authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api/layout"
	tposix "github.com/transparency-dev/tessera/storage/posix"
	"github.com/transparency-dev/tesseract/internal/ct"
	"github.com/transparency-dev/tesseract/internal/x509util"
	"github.com/transparency-dev/tesseract/storage"
	"github.com/transparency-dev/tesseract/storage/posix"
)

const (
	fixtureOrigin = "fsck.example.com"
	// A couple of dozen entries is enough to populate a partial level 0 tile, an entry bundle,
	// and the issuer CAS.
	fixtureEntries = 24
)

var (
	// fsckBin is the path to the fsck binary under test, built by TestMain.
	fsckBin string
	// fixtureLog is the path to a valid log which tests copy and (optionally) corrupt.
	fixtureLog string
	// fixturePubKey is fixtureLog's checkpoint verification key, in the base64 DER form --public_key wants.
	fixturePubKey string
)

// TestMain builds the fsck binary and a small valid log for the tests to work with.
//
// The tests must exercise the binary rather than the fsck library because the behaviour under
// test - turning a failed check into a non-zero exit status - lives entirely in main.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "fsck-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	os.Exit(func() int {
		defer func() {
			if err := os.RemoveAll(tmp); err != nil {
				fmt.Fprintf(os.Stderr, "RemoveAll(%q): %v\n", tmp, err)
			}
		}()

		fsckBin = filepath.Join(tmp, "fsck")
		if out, err := exec.Command("go", "build", "-o", fsckBin, ".").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to build fsck: %v\n%s", err, out)
			return 1
		}

		fixtureLog = filepath.Join(tmp, "log")
		if fixturePubKey, err = createLog(context.Background(), fixtureLog, fixtureEntries); err != nil {
			fmt.Fprintf(os.Stderr, "failed to create fixture log: %v\n", err)
			return 1
		}

		return m.Run()
	}())
}

func TestFsck(t *testing.T) {
	for _, test := range []struct {
		desc string
		// corrupt damages the copy of the fixture log rooted at dir, or is nil to leave it alone.
		corrupt      func(t *testing.T, dir string)
		wantExit     int
		wantInOutput string
	}{
		{
			desc:     "valid log",
			wantExit: 0,
			// A successful run is the only one which gets as far as logging OK, so this also
			// catches fsck bailing out before it has checked anything.
			wantInOutput: "OK",
		}, {
			desc:         "corrupt level 0 tile",
			corrupt:      func(t *testing.T, dir string) { flipBit(t, filepath.Join(dir, tilePath())) },
			wantExit:     1,
			wantInOutput: "FAILED",
		}, {
			desc:         "truncated entry bundle",
			corrupt:      func(t *testing.T, dir string) { truncate(t, filepath.Join(dir, entryBundlePath())) },
			wantExit:     1,
			wantInOutput: "FAILED",
		}, {
			desc:    "missing issuer",
			corrupt: func(t *testing.T, dir string) { remove(t, anyIssuer(t, dir)) },
			// Failing for an issuer reason rather than a tree reason is the point of this case: the
			// issuer CAS is checked separately from the Merkle tree.
			wantExit:     1,
			wantInOutput: "couldn't fetch issuer",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "log")
			copyTree(t, fixtureLog, dir)
			if test.corrupt != nil {
				test.corrupt(t, dir)
			}

			cmd := exec.CommandContext(t.Context(), fsckBin,
				"--ui=false",
				"--monitoring_url=file://"+dir,
				"--origin="+fixtureOrigin,
				"--public_key="+fixturePubKey,
				"--N=4")
			// The POSIX driver writes entry bundles uncompressed, so --bundle_compressed stays off.
			out, err := cmd.CombinedOutput()
			gotExit := 0
			exitErr := &exec.ExitError{}
			if errors.As(err, &exitErr) {
				gotExit = exitErr.ExitCode()
			} else if err != nil {
				t.Fatalf("failed to run fsck: %v\n%s", err, out)
			}

			if gotExit != test.wantExit {
				t.Errorf("fsck exited %d, want %d\n%s", gotExit, test.wantExit, out)
			}
			if !strings.Contains(string(out), test.wantInOutput) {
				t.Errorf("fsck output does not contain %q\n%s", test.wantInOutput, out)
			}
		})
	}
}

// createLog writes a valid static-ct log containing n entries to dir, and returns the base64 DER
// encoded public key its checkpoints are signed with.
func createLog(ctx context.Context, dir string, n int) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate log key: %v", err)
	}
	cpSigner, err := ct.NewCpSigner(key, fixtureOrigin, systemTimeSource{})
	if err != nil {
		return "", fmt.Errorf("failed to create checkpoint signer: %v", err)
	}

	driver, err := tposix.New(ctx, tposix.Config{Path: dir})
	if err != nil {
		return "", fmt.Errorf("failed to create POSIX driver: %v", err)
	}
	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(cpSigner).
		WithCTLayout().
		WithCheckpointInterval(100*time.Millisecond).
		WithBatching(uint(n), 10*time.Millisecond)
	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create appender: %v", err)
	}
	defer func() {
		if err := shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "appender shutdown: %v\n", err)
		}
	}()

	issuerStorage, err := posix.NewIssuerStorage(ctx, dir)
	if err != nil {
		return "", fmt.Errorf("failed to create issuer storage: %v", err)
	}
	s, err := storage.NewCTStorage(ctx, &storage.CTStorageOptions{
		Appender:            appender,
		Reader:              reader,
		IssuerStorage:       issuerStorage,
		AwaiterPollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create CT storage: %v", err)
	}

	// Every entry is chained through an intermediate so that the issuer CAS is populated; more
	// than one intermediate means removing a single issuer leaves part of the log checkable.
	intermediates, err := newCAChain(2)
	if err != nil {
		return "", err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate leaf key: %v", err)
	}

	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 10*time.Millisecond)
	var last tessera.IndexFuture
	for i := range n {
		issuer := intermediates[i%len(intermediates)]
		leaf, err := newCert(int64(100+i), &x509.Certificate{Subject: pkix.Name{CommonName: fmt.Sprintf("leaf-%d.example.com", i)}}, issuer.cert, leafKey.Public(), issuer.key)
		if err != nil {
			return "", err
		}
		chain := []*x509.Certificate{leaf.cert, issuer.cert}

		if err := s.AddIssuerChain(ctx, chain[1:]); err != nil {
			return "", fmt.Errorf("failed to store issuers: %v", err)
		}
		entry, err := x509util.EntryFromChain(chain, false, uint64(time.Now().UnixMilli()))
		if err != nil {
			return "", fmt.Errorf("failed to build entry: %v", err)
		}
		if last, err = s.Add(ctx, entry); err != nil {
			return "", fmt.Errorf("failed to add entry: %v", err)
		}
	}
	// Awaiting the final entry ensures every entry is integrated and covered by a published checkpoint.
	if _, _, err := awaiter.Await(ctx, last); err != nil {
		return "", fmt.Errorf("failed to await publication: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// systemTimeSource implements ct.TimeSource using the wall clock.
type systemTimeSource struct{}

func (systemTimeSource) Now() time.Time { return time.Now() }

type keyedCert struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newCAChain returns n intermediate CAs, all issued by a freshly minted root.
func newCAChain(n int) ([]keyedCert, error) {
	rootTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "fsck test root"},
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	root, err := newCert(1, rootTmpl, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	r := make([]keyedCert, 0, n)
	for i := range n {
		tmpl := &x509.Certificate{
			Subject:               pkix.Name{CommonName: fmt.Sprintf("fsck test intermediate %d", i)},
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		c, err := newCert(int64(10+i), tmpl, root.cert, nil, root.key)
		if err != nil {
			return nil, err
		}
		r = append(r, c)
	}
	return r, nil
}

// newCert issues a certificate from tmpl.
//
// A nil parent, pub or signer means "self-signed with a newly generated key".
func newCert(serial int64, tmpl *x509.Certificate, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (keyedCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return keyedCert{}, fmt.Errorf("failed to generate key: %v", err)
	}
	if pub == nil {
		pub = key.Public()
	}
	if signer == nil {
		signer = key
	}
	tmpl.SerialNumber = big.NewInt(serial)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return keyedCert{}, fmt.Errorf("failed to create certificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return keyedCert{}, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return keyedCert{cert: c, key: key}, nil
}

// tilePath returns the path of the log's level 0 tile, relative to the log root.
//
// Corrupting anything else under tile/0 would be pointless: the log is smaller than a full tile,
// so obsolete partial tiles left behind by the appender are never fetched by fsck.
func tilePath() string {
	return filepath.FromSlash(layout.TilePath(0, 0, layout.PartialTileSize(0, 0, fixtureEntries)))
}

// entryBundlePath returns the path of the log's only entry bundle, relative to the log root.
func entryBundlePath() string {
	return filepath.FromSlash("tile/data/" + layout.NWithSuffix(0, 0, layout.PartialTileSize(0, 0, fixtureEntries)))
}

// anyIssuer returns the path of one of the issuers in the log rooted at dir.
func anyIssuer(t *testing.T, dir string) string {
	t.Helper()
	issuerDir := filepath.Join(dir, "issuer")
	des, err := os.ReadDir(issuerDir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", issuerDir, err)
	}
	if len(des) == 0 {
		t.Fatalf("no issuers in %q", issuerDir)
	}
	return filepath.Join(issuerDir, des[0].Name())
}

func flipBit(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	if len(b) == 0 {
		t.Fatalf("%q is empty", path)
	}
	b[0] ^= 1
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func truncate(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	if err := os.Truncate(path, fi.Size()/2); err != nil {
		t.Fatalf("Truncate(%q): %v", path, err)
	}
}

func remove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove(%q): %v", path, err)
	}
}

// copyTree recursively copies the directory tree rooted at from to to.
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	if err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0644)
	}); err != nil {
		t.Fatalf("failed to copy %q to %q: %v", from, to, err)
	}
}
