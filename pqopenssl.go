package oqsopenssl

import (
	"fmt"
	"os/exec"
	"io"
	"os"
	"path/filepath"
)

var (
	defaultdir = getParentDirectory() 
)

func getParentDirectory() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return filepath.Dir(dir)
}

// runDockerCommand executes a command inside the Docker container.
func runDockerCommand(command []string) error {
	cmd := exec.Command(
		"docker", "run", "--rm",
		"-v", fmt.Sprintf("%s:%s", defaultdir, defaultdir),
		"openquantumsafe/curl",
	)
	cmd.Args = append(cmd.Args, command...)

	fmt.Println("Running Docker command:", cmd.String())
	return runCommand(cmd, "Failed to run Docker command")
}

// GeneratePrivateKey generates a private key using a specified algorithm.
func GeneratePrivateKey(algorithm, outputFile string) error {
	cmd := []string{
		"sh", "-c", fmt.Sprintf("cd %s && openssl genpkey -algorithm %s -out %s", defaultdir, algorithm, outputFile),
	}
	return runDockerCommand(cmd)
}


// GenerateRootCertificate creates a root CA certificate with Basic Constraints for CA.
func GenerateRootCertificate(algorithm, keyFile, outputFile, subj, spiffeID, configFile string, days int) error {

	cmd := []string{
		"sh", "-c", fmt.Sprintf("openssl req -x509 -newkey %s -keyout "+defaultdir+"/%s -out "+defaultdir+"/%s -days %d -subj %s -config %s -extensions v3_ca -nodes",
			algorithm, keyFile, outputFile, days, subj, configFile),
	}
	return runDockerCommand(cmd)
}

// GenerateCSR generates a certificate signing request (CSR) for the server.
func GenerateCSR(algorithm, csrKey, csrFile, subj, spiffeID, configFile string) error {
	cmd := []string{
		"sh", "-c", fmt.Sprintf(`openssl req -nodes -new -newkey %s -keyout %s -out %s -subj %s -config %s`, algorithm, csrKey, csrFile, subj, configFile),
	}
	return runDockerCommand(cmd)
}

// SignCertificate signs the server certificate with the CA certificate.
func SignCertificate(csrFile, caCertFile, caKeyFile, spiffeID, outputFile string, days int) error {
	cmd := []string{
		"sh", "-c", fmt.Sprintf(
			`echo "subjectAltName=URI:%s" > `+defaultdir+`/extfile.conf && openssl x509 -req -in %s -CA %s -CAkey %s -CAcreateserial -out %s -days %d -extfile `+defaultdir+`/extfile.conf && rm `+defaultdir+`/extfile.conf`,
			spiffeID, csrFile, caCertFile, caKeyFile, outputFile, days,
		),
	}
	return runDockerCommand(cmd)
}

// StartServer starts an OpenSSL server on the specified port with the given certificate and private key.
func StartServer(port int, certFile, keyFile, caFile string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	cmd := exec.Command(
		"docker", "run", "--rm",
		"--network", "host",
		"-v", fmt.Sprintf("%s:%s", defaultdir, defaultdir), // Mount the current directory for access to cert and key files
		// "-p", fmt.Sprintf("%d:%d", port, port),
		"openquantumsafe/curl",
		"sh", "-c", fmt.Sprintf(
			`openssl s_server -accept %d -state -cert %s/server/%s -key %s/server/%s -tls1_3 -Verify 1 -CAfile %s -www -ignore_unexpected_eof -provider oqsprovider`,
			port, defaultdir, certFile, defaultdir, keyFile, caFile),
	)
	fmt.Printf("Running command: %s\n", cmd)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}

	return cmd, stdinPipe, stdoutPipe, nil
}


func StartClient(address, certFile, keyFile, caCertFile string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	cmd := exec.Command(
		"docker", "run", "--rm",
		"--network", "host",
		"-v", fmt.Sprintf("%s:%s", defaultdir, defaultdir),
		"openquantumsafe/curl",
		"sh", "-c", fmt.Sprintf(
			`openssl s_client -connect %s -tls1_3 -state -cert %s/client/%s -key %s/client/%s -CAfile %s -provider oqsprovider`,
			address, defaultdir, certFile, defaultdir, keyFile, caCertFile),
	)
	fmt.Printf("Running client command: %s\n", cmd)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}

	return cmd, stdinPipe, stdoutPipe, nil
}

// runCommand executes an exec.Command and captures its output.
func runCommand(cmd *exec.Cmd, errorMessage string) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s\n%s", errorMessage, err, string(output))
	}
	fmt.Println(string(output)) // Print command output for logging
	return nil
}

// ValidateCertificate checks if the provided certificate is valid against the specified CA certificate.
func ValidateCertificate(certFile, caCertFile string) error {
	cmd := exec.Command("openssl", "verify", "-CAfile", caCertFile, certFile)
	return runCommand(cmd, "Failed to validate certificate")
}