"""
Typo-squatting heuristics: a dependency whose name is one keystroke or
one look-alike character away from a widely used package, but is not
that package, is a classic malicious-package delivery vector.
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.repository.manifests import normalize_package
from backend.repository.versions import NPM, PYPI, RUBYGEMS


# The most depended-upon packages per registry. A name close to one of
# these is suspicious; a name close to an obscure package is not.
def _names(text: str) -> frozenset[str]:
    return frozenset(text.split())


POPULAR: dict[str, frozenset[str]] = {
    PYPI: _names(
        """
        requests urllib3 numpy pandas boto3 botocore setuptools six python-dateutil
        certifi idna charset-normalizer typing-extensions packaging pyyaml cryptography
        flask django jinja2 markupsafe click werkzeug itsdangerous sqlalchemy pydantic
        fastapi uvicorn starlette gunicorn celery redis psycopg2 psycopg2-binary pymysql
        pillow matplotlib scipy scikit-learn tensorflow torch keras transformers
        beautifulsoup4 lxml selenium pytest coverage tox mock pyjwt jsonschema attrs
        aiohttp httpx grpcio protobuf google-api-core google-auth awscli colorama tqdm
        pytz tzdata simplejson ujson orjson rich docutils sphinx wheel pip virtualenv
        paramiko pyopenssl rsa pycparser cffi greenlet wrapt decorator toml tomli
        openpyxl xlrd marshmallow alembic pymongo elasticsearch kafka-python
        python-dotenv dnspython bcrypt passlib asn1crypto ldap3 pexpect pyasn1 nltk
        """
    ),
    NPM: _names(
        """
        react react-dom lodash express axios chalk commander debug moment request
        vue angular typescript webpack babel-core eslint prettier jest mocha chai
        underscore async bluebird uuid yargs minimist glob rimraf mkdirp fs-extra
        dotenv jquery body-parser cors cookie-parser jsonwebtoken bcrypt mongoose
        mysql pg redis socket.io ws node-fetch cross-env nodemon next nuxt rxjs
        classnames prop-types styled-components redux react-redux react-router
        semver colors inquirer ora tslib core-js regenerator-runtime dayjs date-fns
        qs cheerio puppeteer sharp handlebars ejs pug marked highlight.js
        webpack-cli vite rollup esbuild postcss autoprefixer tailwindcss sass less
        """
    ),
    RUBYGEMS: _names(
        """
        rails rake bundler rack nokogiri json activesupport thor puma devise rspec
        sinatra sidekiq pg mysql2 redis faraday httparty aws-sdk
        """
    ),
}

HOMOGLYPHS = (("0", "o"), ("1", "l"), ("rn", "m"), ("vv", "w"), ("5", "s"), ("i", "l"))


def damerau_levenshtein(left: str, right: str, limit: int = 2) -> int:
    """Edit distance counting a transposition as one edit, capped at ``limit + 1``."""

    if abs(len(left) - len(right)) > limit:
        return limit + 1

    previous_previous: list[int] = []
    previous = list(range(len(right) + 1))

    for i, a in enumerate(left, start=1):
        current = [i] + [0] * len(right)

        for j, b in enumerate(right, start=1):
            cost = 0 if a == b else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)

            if i > 1 and j > 1 and a == right[j - 2] and left[i - 2] == b:
                current[j] = min(current[j], previous_previous[j - 2] + 1)

        if min(current) > limit:
            return limit + 1

        previous_previous, previous = previous, current

    return previous[-1]


@dataclass
class TyposquatSignal:
    target: str
    technique: str


def _comparable(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def typosquat_target(ecosystem: str, name: str) -> TyposquatSignal | None:
    popular = POPULAR.get(ecosystem)

    if not popular:
        return None

    candidate = normalize_package(ecosystem, name)

    if candidate in popular:
        return None

    # A scope is part of the identity: "@types/react" is not squatting.
    if candidate.startswith("@"):
        return None

    plain = _comparable(candidate)

    for original in popular:
        if plain == _comparable(original):
            # Same name with different separators, e.g. "python_dateutil".
            if ecosystem != PYPI:
                return TyposquatSignal(original, "separator confusion")
            continue

        for a, b in HOMOGLYPHS:
            if plain.replace(a, b) == original or original.replace(a, b) == plain:
                return TyposquatSignal(original, "look-alike characters")

        if len(original) >= 5 and damerau_levenshtein(plain, original, 1) == 1:
            return TyposquatSignal(original, "one-character edit")

    return None
