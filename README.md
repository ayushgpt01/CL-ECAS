# Certificate-less Elliptic Curve Aggregate Signcryption Scheme

The CL-ECAS App is a Java-based application that demonstrates signcryption, a cryptographic technique that combines the functionalities of digital signatures and encryption into a single operation. The app allows users to create identities, perform signcryption, and unsigncryption using elliptic curve cryptography.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Introduction

The main goal of this project is to showcase the signcryption technique using elliptic curve cryptography. Signcryption provides the advantage of efficient and secure communication by simultaneously ensuring the confidentiality, integrity, and authentication of the transmitted data.

The application consists of two main classes: `KGC` (Key Generation Center) and `User`. The `KGC` class handles the key generation and aggregation of signcrypted data, while the `User` class is responsible for signcryption and unsigncryption operations.

## Features

- Create users with unique identities
- Perform signcryption on user messages
- Aggregate signcrypted data for multiple users
- Perform unsigncryption using aggregated cipher text and public keys of users

## Prerequisites

- Java Development Kit (JDK) 8 or higher
- Apache Maven (for building the project)
- Bouncy Castle Library (download from https://www.bouncycastle.org/download/)

## Installation

1. Clone the repository to your local machine: `git clone https://github.com/ayushgpt01/CL-ECAS.git`

2. Navigate to the project directory: `cd CL-ECAS`

3. Place the Bouncy Castle library (e.g., `bcprov-jdk15on-1.70.jar`) in the `lib` directory.

4. Build the project using Maven:`mvn package`

## Usage

To use the CL-ECAS App, follow these steps:

1. Run the application:

   java -cp target/CL-ECAS.jar:lib/bcprov-jdk15on-1.70.jar com.example.CL-ECAS

2. Follow the on-screen instructions to create users and perform signcryption operations.

3. Use option 3 to perform unsigncryption. Make sure to provide the appropriate user identity when trying to decrypt.

## Contributing

Contributions to the Signcryption App are welcome! If you find any issues or have suggestions for improvement, please create a new issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE]() file for details.

