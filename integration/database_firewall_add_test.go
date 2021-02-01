package integration

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os/exec"
	"strings"
	"testing"

	"github.com/sclevine/spec"
	"github.com/stretchr/testify/require"
)

var _ = suite.Focus("database/firewalls", func(t *testing.T, when spec.G, it spec.S) {
	var (
		expect *require.Assertions
		server *httptest.Server
	)

	it.Before(func() {
		expect = require.New(t)

		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			switch req.URL.Path {
			case "/v2/databases/d168d635-1c88-4616-b9b4-793b7c573927/firewall":
				auth := req.Header.Get("Authorization")
				if auth != "Bearer some-magic-token" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				if req.Method == http.MethodPut {
					reqBody, err := ioutil.ReadAll(req.Body)
					expect.NoError(err)

					expect.JSONEq(databasesAddFirewallRequest, string(reqBody))

					w.Write([]byte(databasesAddFirewallRuleResponse))
				} else if req.Method == http.MethodGet {
					w.Write([]byte(databasesAddFirewallRuleResponse))
				} else {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
			default:
				dump, err := httputil.DumpRequest(req, true)
				if err != nil {
					t.Fatal("failed to dump request")
				}

				t.Fatalf("received unknown request: %s", dump)
			}
		}))
	})

	when("command is add", func() {
		it("add a database cluster's firewall rules", func() {
			cmd := exec.Command(builtBinaryPath,
				"-t", "some-magic-token",
				"-u", server.URL,
				"databases",
				"firewalls",
				"add",
				"d168d635-1c88-4616-b9b4-793b7c573927",
				"--rule", "tag:newFirewall",
			)

			output, err := cmd.CombinedOutput()
			expect.NoError(err, fmt.Sprintf("received error output: %s", output))
			expect.Equal(strings.TrimSpace(databasesAddFirewallRuleOutput), strings.TrimSpace(string(output)))

			expected := strings.TrimSpace(databasesAddFirewallRuleResponse)
			actual := strings.TrimSpace(string(output))

			if expected != actual {
				t.Errorf("expected\n\n%s\n\nbut got\n\n%s\n\n", expected, actual)
			}
		})
	})

})

const (
	databasesAddFirewallRequest = `{"rules": [{"type": "tag","value": "newFirewall"}]}`

	databasesAddFirewallRuleOutput = `
UUID                                    ClusterUUID                             Type    Value          Created At
5cdafe5d-1bd6-4d8d-b59e-f89873106113    d168d635-1c88-4616-b9b4-793b7c573927    tag     newFirewall    2021-02-01 20:07:53 +0000 UTC`

	databasesAddFirewallRuleResponse = `{
		"rules":[
		   {
			  "uuid":"5cdafe5d-1bd6-4d8d-b59e-f89873106113",
			  "cluster_uuid":"d168d635-1c88-4616-b9b4-793b7c573927",
			  "type":"tag",
			  "value":"newFirewall",
			  "created_at":"2021-02-01T18:36:14Z"
		   }
		]
	 }`
)
