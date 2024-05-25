Dynamic DNS Updater
===================

[![version](https://img.shields.io/pypi/v/ddnsu?style=flat-square)][0]
![py](https://img.shields.io/pypi/pyversions/ddnsu?style=flat-square)
[![whl](https://img.shields.io/pypi/wheel/ddnsu?style=flat-square)][1]
[![license](https://img.shields.io/pypi/l/ddnsu?style=flat-square)][2]

DDNSU is a Python 3 script for updating dynamic DNS records. It can
keep track of your last known IP address and detect your current
one to determine if updating records is necessary. Currently, only
Namecheap's DDNS is supported.

## Installation

The recommended way to install `ddnsu` is to use [pip][3] and install
from PyPI:

```bash
python -m pip install ddnsu
```

You can also install from Wheel files available [here][4]:

```bash
python -m pip install './ddnsu-0.0.0.whl'
```

## Usage

Once installed, the `ddnsu` command should be available from the
command line. At minimum, the domain and hosts to be updated and the
DDNS password must be specified. This can be done via command line
options:

```bash
ddnsu --domain example.com --hosts www forum blog --pswd 1234
```

Alternatively, they can be specified in a JSON config file named
`ddnsu_config.json` placed in the working directory:

```json
{
    "schema": 1,
    "config": {
        "pswd": "1234",
        "domain": "example.com",
        "hosts": [
            "www",
            "forum",
            "blog"
        ]
    }
}
```

```bash
# `domain`, `hosts`, and `pswd` supplied by config file
ddnsu --log_level debug
```

All options except `--working_dir` and `--log_level` can be used in
the config file instead of the command line. If an option is used in
both the command line and the config file, the command line value
takes precedence.

## Contributing

Pull requests are welcome. For major changes, please [open an issue][5] first
to discuss what you would like to change.

## License

[MIT][2]


[0]: https://pypi.org/project/ddnsu/

[1]: https://pypi.org/project/ddnsu/#files

[2]: https://opensource.org/license/mit

[3]: https://pip.pypa.io/en/stable/

[4]: https://pypi.org/project/ddnsu/#files

[5]: https://github.com/phillippe/ddnsu/issues
