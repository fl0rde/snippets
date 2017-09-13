# sslsan-utils

This is just a collection of snippets to extract subjectAltName entries from several SSL/TLS services, such as:

* [HTTPS](/de/fl0r/sslsan/sslsanhttps.py)
* [STARTTLS](/de/fl0r/sslsan/sslsansmtp.py)
* [SMTPS](/de/fl0r/sslsan/sslsansmtp.py)
* [Certificate Transparency](/de/fl0r/sslsan/sslsanct.py)

## Getting Started

Example scripts can be found in [/de/fl0r/sslsan](/de/fl0r/sslsan), usages are mentioned in the comment in the files above. Running each script with `python <script> -h` may give you some additional information.

All needed CT and SSL/TLS functions can be found in [/de/fl0r/sslsan/utils](/de/fl0r/sslsan/utils).

### Prerequisites

These scripts are tested using Python 3.6.2 and the following packages: `pyOpenSSL`, `asn1crypto`, `dnspython`

## Authors

* **Florian Ammon** - Twitter: [@riesenwildschaf](https://twitter.com/riesenwildschaf)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
