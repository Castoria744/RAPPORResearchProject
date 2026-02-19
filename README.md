Research Project for University of Auckland (Late upload, stuck on my PC trying to format stuff, haven't uploaded  back then)

Privacy Research and a bit of Cyber Sec

Key Goal
- 
Eliminate/Change PII to a noise to preserve privacy

# RAPPOR: Randomized Aggregatable Privacy-Preserving Ordinal Response

## Overview
RAPPOR (Randomized Aggregatable Privacy-Preserving Ordinal Response) is a technology for crowdsourcing statistics from end-user software while maintaining strong privacy guarantees. 

Developed by Google, it allows for the collection of data about software usage and behavior without compromising the confidentiality of individual users. It achieves this by using **Differential Privacy**—specifically, by adding "random noise" to data before it is sent, ensuring that aggregate trends can be measured while individual inputs remain anonymous.

## Key Features
- **Privacy-Preserving**: Individual data points are obfuscated using randomized response techniques.
- **High Utility**: Allows for accurate statistical analysis of large populations.
- **Cybersecurity Applications**: Useful for tracking malware, identifying common vulnerabilities, and monitoring system telemetry without tracking specific users. 

## How it Works
RAPPOR uses a "flip of a coin" logic:
1. A user's actual data is processed.
2. Based on a set probability, the data is either reported truthfully or replaced with a random value.
3. When millions of reports are combined, the "noise" cancels out, leaving accurate statistics for the whole group.

## License & Attribution
This project includes code and concepts originally developed by **Google**. 

- **Original Author**: Google LLC
- **Original Repository**: [google/rappor](https://github.com/google/rappor)
- **License**: This project is distributed under the **Apache License 2.0** (which is the license used by the original Google repository). 

*Note: If you are using this code, please ensure you keep the original LICENSE file in the root directory to comply with attribution requirements.*

---
*Disclaimer: This repository is a distribution/implementation of the RAPPOR technology. Please refer to the original Google research papers for technical depth.*
