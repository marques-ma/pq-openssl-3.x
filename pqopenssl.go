package oqsopenssl

import (
	"fmt"
	"os/exec"
	"os"
	"path/filepath"
	"encoding/json"
	"time"
)

var (
	defaultdir = getParentDirectory() 
	containerID   = ""

)

func getParentDirectory() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return filepath.Dir(dir)
}

// GeneratePrivateKey generates a private key using a specified algorithm.
func GeneratePrivateKey(algorithm, outputFile string) error {
	cmd := []string{
		"sh", "-c", fmt.Sprintf(`openssl genpkey -algorithm %s -out %s`, algorithm, outputFile),
	}
	return runDockerExecCommand(cmd)
}

// GenerateRootCertificate creates a root CA certificate with Basic Constraints for CA.
func GenerateRootCertificate(algorithm, keyFile, outputFile, subj, spiffeID, configFile string, days int) error {
	// defer timeTrack(time.Now(), "GenerateRootCertificate")

	cmd := []string{
		"sh", "-c", fmt.Sprintf(`openssl req -x509 -sha384 -newkey %s -keyout `+defaultdir+`/%s -out `+defaultdir+`/%s -days %d -subj %s -config %s -extensions v3_ca -nodes`,
			algorithm, keyFile, outputFile, days, subj, configFile),
	}
	return runDockerExecCommand(cmd)
}

// GenerateCSR generates a certificate signing request (CSR) for the server.
func GenerateCSR(algorithm, csrKey, csrFile, subj, spiffeID, configFile string) error {
	// defer timeTrack(time.Now(), "GenerateCSR")

	cmd := []string{
		"sh", "-c", fmt.Sprintf(`openssl req -nodes -new -newkey %s -keyout %s -out %s -subj %s -config %s`, algorithm, csrKey, csrFile, subj, configFile),
	}
	return runDockerExecCommand(cmd)
}

// SignCertificate signs the certificate with the CA certificate.
func SignCertificate(csrFile, caCertFile, caKeyFile, spiffeID, outputFile string, days int) error {
	// defer timeTrack(time.Now(), "SignCertificate")

	cmd := []string{
		"sh", "-c", fmt.Sprintf(
			`echo "subjectAltName=URI:%s" > `+defaultdir+`/extfile.conf && openssl x509 -req -in %s -CA %s -CAkey %s -CAcreateserial -out %s -days %d -extfile `+defaultdir+`/extfile.conf && rm `+defaultdir+`/extfile.conf`,
			spiffeID, csrFile, caCertFile, caKeyFile, outputFile, days,
		),
	}
	return runDockerExecCommand(cmd)
}

// runCommand executes an exec.Command and captures its output.
func runCommand(cmd *exec.Cmd, errorMessage string) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s\n%s", errorMessage, err, string(output))
	}
	// fmt.Println(string(output)) // Print command output for logging
	return nil
}

// ValidateCertificate checks if the provided certificate is valid against the specified CA certificate.
func ValidateCertificate(certFile, caCertFile string) error {
	// defer timeTrack(time.Now(), "ValidateCertificate")

	cmd := []string{
		"sh", "-c", fmt.Sprintf(
			`openssl verify -CAfile %s %s`, caCertFile, certFile,
		),
	}
	return runDockerExecCommand(cmd)
}

func timeTrack(start time.Time, name string) error {
	elapsed := time.Since(start)
	fmt.Printf("\n%s execution time is %s\n", name, elapsed)

	// If the file doesn't exist, create it, or append to the file
	file, err := os.OpenFile("./bench.data", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("Failed creating benchmark file: %w", err)
	}
	// log.Printf("Writing to file...")
	json.NewEncoder(file).Encode(fmt.Sprintf("%s, %s", name, elapsed))
	if err := file.Close(); err != nil {
		return fmt.Errorf("Failed encoding results: %w",err)
	}
	return nil
}

// StartOQSContainer starts a persistent Docker container with oqsprovider running.
func StartOQSContainer() error {
	cmd := exec.Command("docker", "run", "-d", "--rm", 
		"--network", "host", 
		"-v", fmt.Sprintf("%s:%s", defaultdir, defaultdir), 
		"openquantumsafe/curl", "sleep", "infinity")
	
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to start oqsprovider container: %w", err)
	}
	
	containerID = string(output[:12]) // Store the first 12 chars of the container ID
	fmt.Printf("OQS provider container started with ID: %s\n", containerID)
	return nil
}

// StopOQSContainer stops the running OQS Docker container.
func StopOQSContainer() error {
	if containerID == "" {
		return fmt.Errorf("no running container to stop")
	}
	cmd := exec.Command("docker", "stop", containerID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop oqsprovider container: %w, output: %s", err, string(output))
	}
	fmt.Printf("OQS provider container stopped with ID: %s\n", containerID)
	return nil
}

// runDockerExecCommand executes a command inside the existing Docker container.
func runDockerExecCommand(command []string) error {
	if containerID == "" {
		return fmt.Errorf("OQS provider container is not running")
	}
	
	// Corrected exec.Command usage by ensuring each part of the command is a separate argument
	cmd := append([]string{"docker", "exec", containerID}, command...)
	// fmt.Println("Running Docker command:", cmd)

	return runCommand(exec.Command(cmd[0], cmd[1:]...), "Failed to run command in OQS container")
}
