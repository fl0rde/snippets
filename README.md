# sslsan-utils

This is just a collection of snippets to extract subjectAltName entries from several SSL/TLS services, such as:

* HTTPS
* STARTTLS
* SMTPS
* Certificate-Transparency

## Getting Started

Example scripts can be found in [/de/fl0r/sslsan](/de/fl0r/sslsan), usages are mentioned in the comment in the files above. Running each script with `python <script> -h` may give you some additional information.

All beeded CT and SSL/TLS functions can be found in [/de/fl0r/sslsan/utils](/de/fl0r/sslsan/utils).

### Prerequisites

These scripts are tested using Python 3.6.2 and the following packages: `pyOpenSSL`, `asn1crypto`, `dnspython`

## Authors

* **Florian Ammon** - Twitter: [@riesenwildschaf](https://twitter.com/riesenwildschaf)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
