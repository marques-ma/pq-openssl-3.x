[![DOI](https://zenodo.org/badge/886867653.svg)](https://doi.org/10.5281/zenodo.14902218)
# Overview

This package leverages the [OQS-Provider](https://github.com/open-quantum-safe/oqs-provider) container to allow the integration of its functionalities with minimal requirements impact and focus in potentializing the development of post-quantum proof of concepts in Go language.  

# Requirements
Since this package wrap the OQS-provider container, it requires Docker ^1.23.0 to run.

# List of functions
| Function Name  | Description |
|---------------|------------|
| `GeneratePrivateKey(algorithm, outputFile string)`     | Generates a private key using the specified algorithm |
| `GenerateRootCertificate(algorithm, keyFile, outputFile, subj, spiffeID, configFile string, days int)`     | Generates a root CA certificate with Basic Constraints |
| `GenerateCSR(algorithm, csrKey, csrFile, subj, spiffeID, configFile string)`     | Generates a certificate signing request (CSR) |
| `SignCertificate(csrFile, caCertFile, caKeyFile, spiffeID, outputFile string, days int)`     | Signs the certificate using the CA certificate |
| `ValidateCertificate(certFile, caCertFile string)`     | Checks if the provided certificate is valid using the provided certificate |
| `StartOQSContainer()`     | Starts a persistent Docker container with oqsprovider running |
| `StopOQSContainer()`     | Stops the running OQS Docker container |
| `BenchmarkAlgorithm(algorithm, resultFile string, duration int)`     | Benchmarks an OpenSSL algorithm and saves the results to a file |

# How to use
1 - In your GO code, add the package `"github.com/marques-ma/pq-openssl-3.x"` in the import list  
2 - Start the OQS-Provider container with `StartOQSContainer()`  
3 - Execute the necessary functions  
4 - Stop the OQS-Provider container with `StopOQSContainer()`  
