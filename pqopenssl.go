package oqsopenssl

import (
	"fmt"
	"os/exec"
	"os"
	"path/filepath"
	"encoding/json"
	"time"
	"sync"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/load"
)

var (
	defaultdir = getParentDirectory() 
	containerID   = ""

)

// BenchmarkResult holds the results of the benchmark and system metrics.
type BenchmarkResult struct {
	Algorithm      string        `json:"algorithm"`
	Duration       int           `json:"duration_seconds"`
	CommandOutput  string        `json:"command_output"`
	ExecutionTime  string        `json:"execution_time"`
	CPUUsage       float64       `json:"cpu_usage_percent"`
	MemoryUsage    float64       `json:"memory_usage_mb"`
	LoadAverage    float64       `json:"load_average"`
	Timestamp      time.Time     `json:"timestamp"`
	Inputs         map[string]interface{} `json:"inputs"` 

}

// SystemMetrics stores a snapshot of CPU, memory, and load average.
type SystemMetrics struct {
	CPUUsage    float64
	MemoryUsage float64
	LoadAverage float64
}

func getParentDirectory() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return filepath.Dir(dir)
}

// GeneratePrivateKey generates a private key using a specified algorithm.
func GeneratePrivateKey(algorithm, outputFile string) error {
	defer timeTrack(time.Now(), "GeneratePrivateKey")

	cmd := []string{
		"sh", "-c", fmt.Sprintf(`openssl genpkey -algorithm %s -out %s`, algorithm, outputFile),
	}
	return RunDockerExecCommand(cmd)
}

// GenerateRootCertificate creates a root CA certificate with Basic Constraints for CA.
func GenerateRootCertificate(algorithm, keyFile, outputFile, subj, spiffeID, configFile string, days int) error {
	defer timeTrack(time.Now(), "GenerateRootCertificate")

	cmd := []string{
		"sh", "-c", fmt.Sprintf(`openssl req -x509 -sha384 -newkey %s -keyout `+defaultdir+`/%s -out `+defaultdir+`/%s -days %d -subj %s -config %s -extensions v3_ca -nodes`,
			algorithm, keyFile, outputFile, days, subj, configFile),
	}
	return RunDockerExecCommand(cmd)
}

// GenerateCSR generates a certificate signing request (CSR) for the server.
func GenerateCSR(algorithm, csrKey, csrFile, subj, spiffeID, configFile string) error {
	defer timeTrack(time.Now(), "GenerateCSR")

	cmd := []string{
		"sh", "-c", fmt.Sprintf(`openssl req -nodes -new -newkey %s -keyout %s -out %s -subj %s -config %s`, algorithm, csrKey, csrFile, subj, configFile),
	}
	return RunDockerExecCommand(cmd)
}

// SignCertificate signs the certificate with the CA certificate.
func SignCertificate(csrFile, caCertFile, caKeyFile, spiffeID, outputFile string, days int) error {
	defer timeTrack(time.Now(), "SignCertificate")

	cmd := []string{
		"sh", "-c", fmt.Sprintf(
			`echo "subjectAltName=URI:%s" > `+defaultdir+`/extfile.conf && openssl x509 -req -in %s -CA %s -CAkey %s -CAcreateserial -out %s -days %d -extfile `+defaultdir+`/extfile.conf && rm `+defaultdir+`/extfile.conf`,
			spiffeID, csrFile, caCertFile, caKeyFile, outputFile, days,
		),
	}
	return RunDockerExecCommand(cmd)
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
	defer timeTrack(time.Now(), "ValidateCertificate")

	cmd := []string{
		"sh", "-c", fmt.Sprintf(
			`openssl verify -CAfile %s %s`, caCertFile, certFile,
		),
	}
	return RunDockerExecCommand(cmd)
}

func timeTrack(start time.Time, name string) error {
	elapsed := time.Since(start)
	// fmt.Printf("\n%s execution time is %s\n", name, elapsed)

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

// RunDockerExecCommand executes a command inside the existing Docker container.
func RunDockerExecCommand(command []string) error {
	if containerID == "" {
		return fmt.Errorf("OQS provider container is not running")
	}
	
	// Corrected exec.Command usage by ensuring each part of the command is a separate argument
	cmd := append([]string{"docker", "exec", containerID}, command...)
	// fmt.Println("Running Docker command:", cmd)

	return runCommand(exec.Command(cmd[0], cmd[1:]...), "Failed to run command in OQS container")
}

// BenchmarkAlgorithm benchmarks an OpenSSL algorithm and saves the results to a file.
func BenchmarkAlgorithm(algorithm, resultFile string, duration int) error {
	// defer timeTrack(time.Now(), "BenchmarkAlgorithm")

	if containerID == "" {
		return fmt.Errorf("OQS provider container is not running")
	}

	// Construct the command to benchmark the algorithm.
	cmd := []string{
		"sh", "-c", fmt.Sprintf(`openssl speed -seconds %d %s > %s`, duration, algorithm, filepath.Join(defaultdir, resultFile)),
	}

	err := RunDockerExecCommand(cmd)
	if err != nil {
		return fmt.Errorf("failed to benchmark algorithm %s: %w", algorithm, err)
	}

	fmt.Printf("Benchmark results for %s saved to %s\n", algorithm, resultFile)
	return nil
}

// NewBenchmarkAlgorithm runs the OpenSSL benchmark, monitors system metrics, and saves detailed results.
func NewBenchmarkAlgorithm(algorithm, resultFile string, duration int) error {
	var wg sync.WaitGroup
	metricsChan := make(chan SystemMetrics, 100)
	stopChan := make(chan bool)

	// // Capture initial system metrics
	// initialMetrics, err := captureSystemMetrics()
	// if err != nil {
	// 	return fmt.Errorf("failed to capture initial system metrics: %w", err)
	// }

	// Start monitoring in a separate goroutine
	wg.Add(1)
	go monitorSystemMetrics(metricsChan, stopChan, &wg)

	// Construct the command to benchmark the algorithm.
	cmd := []string{
		"sh", "-c", fmt.Sprintf(`openssl speed -seconds %d %s > %s`, duration, algorithm, filepath.Join(defaultdir, resultFile)),
	}

	startTime := time.Now()

	// Execute the Docker command
	err := RunDockerExecCommand(cmd)
	if err != nil {
		return fmt.Errorf("failed to benchmark algorithm %s: %w", algorithm, err)
	}

	executionTime := time.Since(startTime)

	// Stop monitoring
	close(stopChan)
	wg.Wait()

	// Collect all metrics
	close(metricsChan)
	var metrics []SystemMetrics
	for metric := range metricsChan {
		metrics = append(metrics, metric)
	}

	// Compute averages and include initial metrics
	avgCPU, avgMem, avgLoad := calculateAverages(metrics)

	// Compile benchmark result
	result := BenchmarkResult{
		Algorithm:         algorithm,
		Duration:   duration,
		// CommandOutput:     string(output), // Include the OpenSSL command output
		ExecutionTime:     executionTime.String(),
		// InitialCPUUsage:   initialMetrics.CPUUsage,
		// InitialMemoryUsage: initialMetrics.MemoryUsage,
		CPUUsage:   avgCPU,
		MemoryUsage:     avgMem,
		LoadAverage:       avgLoad,
		// SystemMetrics:     metrics, // Include all sampled metrics
		Inputs: map[string]interface{}{
			"openssl_command": fmt.Sprintf("openssl speed -seconds %d %s", duration, algorithm),
			// "container_name":  containerName,
		},
		Timestamp: time.Now(),
	}

	// Save results to the specified file
	file, err := os.Create(resultFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to write benchmark results: %w", err)
	}

	fmt.Printf("Benchmark completed and saved to %s\n", resultFile)
	return nil
}

// monitorSystemMetrics continuously collects system metrics.
func monitorSystemMetrics(metricsChan chan<- SystemMetrics, stopChan <-chan bool, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-stopChan:
			return
		default:
			cpuUsage, _ := cpu.Percent(0, false)
			memUsage, _ := mem.VirtualMemory()
			loadAvg, _ := load.Avg()

			metricsChan <- SystemMetrics{
				CPUUsage:    cpuUsage[0],
				MemoryUsage: float64(memUsage.Used) / (1024 * 1024), // Convert bytes to MB
				LoadAverage: loadAvg.Load1,
			}
			time.Sleep(1 * time.Second) // Collect metrics every second
		}
	}
}

// calculateAverages computes average values from collected metrics.
func calculateAverages(metrics []SystemMetrics) (float64, float64, float64) {
	var totalCPU, totalMem, totalLoad float64
	for _, metric := range metrics {
		totalCPU += metric.CPUUsage
		totalMem += metric.MemoryUsage
		totalLoad += metric.LoadAverage
	}
	count := float64(len(metrics))
	return totalCPU / count, totalMem / count, totalLoad / count
}