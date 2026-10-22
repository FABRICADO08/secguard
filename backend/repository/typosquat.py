"""
Typo-squatting heuristics: a dependency whose name is one keystroke or
one look-alike character away from a widely used package, but is not
that package, is a classic malicious-package delivery vector.
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.repository.manifests import normalize_package
from backend.repository.versions import (
    CARGO,
    COCOAPODS,
    MAVEN,
    NPM,
    NUGET,
    PUB,
    PYPI,
    RUBYGEMS,
    SWIFT,
)


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
    NUGET: _names(
        """
        newtonsoft.json serilog serilog.sinks.console automapper dapper polly moq xunit
        nunit fluentvalidation mediatr swashbuckle.aspnetcore castle.core bouncycastle
        restsharp npgsql stackexchange.redis nlog log4net autofac humanizer csvhelper
        fluentassertions hangfire mongodb.driver awssdk.core
        """
    ),
    MAVEN: _names(
        """
        com.fasterxml.jackson.core:jackson-databind com.fasterxml.jackson.core:jackson-core
        com.google.guava:guava org.apache.commons:commons-lang3 commons-io:commons-io
        org.slf4j:slf4j-api ch.qos.logback:logback-classic org.apache.logging.log4j:log4j-core
        junit:junit org.junit.jupiter:junit-jupiter org.mockito:mockito-core
        com.google.code.gson:gson org.projectlombok:lombok org.yaml:snakeyaml
        com.squareup.okhttp3:okhttp com.squareup.retrofit2:retrofit org.postgresql:postgresql
        mysql:mysql-connector-java org.springframework:spring-core org.hibernate:hibernate-core
        io.netty:netty-all org.apache.httpcomponents:httpclient commons-codec:commons-codec
        """
    ),
    CARGO: _names(
        """
        serde serde_json serde_derive tokio rand regex clap anyhow thiserror log
        env_logger tracing reqwest hyper futures chrono lazy_static once_cell bytes
        itertools syn quote proc-macro2 libc base64 uuid url axum actix-web sqlx diesel
        rayon crossbeam parking_lot hashbrown smallvec time toml openssl rustls ring
        """
    ),
    PUB: _names(
        """
        http provider shared_preferences path_provider dio intl url_launcher
        flutter_bloc bloc get_it equatable json_annotation cached_network_image
        image_picker firebase_core firebase_auth cloud_firestore sqflite rxdart
        go_router riverpod flutter_riverpod connectivity_plus device_info_plus
        package_info_plus permission_handler flutter_svg uuid logger collection
        """
    ),
    SWIFT: _names(
        """
        github.com/alamofire/alamofire github.com/apple/swift-nio github.com/apple/swift-log
        github.com/apple/swift-argument-parser github.com/apple/swift-collections
        github.com/apple/swift-algorithms github.com/onevcat/kingfisher
        github.com/snapkit/snapkit github.com/realm/realm-swift github.com/firebase/firebase-ios-sdk
        github.com/reactivex/rxswift github.com/vapor/vapor github.com/pointfreeco/swift-composable-architecture
        github.com/swiftyjson/swiftyjson github.com/airbnb/lottie-ios
        """
    ),
    COCOAPODS: _names(
        """
        alamofire afnetworking sdwebimage kingfisher snapkit masonry swiftyjson
        rxswift rxcocoa realmswift firebase googlesignin lottie-ios moya
        iqkeyboardmanagerswift mbprogresshud fbsdkcorekit charts
        """
    ),
}

# Registries where "-" and "_" (and ".") spell the same package.
SEPARATOR_INSENSITIVE = frozenset({PYPI, CARGO})

# nuget.org prefixes reserved by their owners: nobody else can publish under them.
NUGET_RESERVED = frozenset({"microsoft", "system", "azure", "awssdk"})

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


def _homoglyph_match(plain: str, original: str) -> bool:
    return any(
        plain.replace(a, b) == original or original.replace(a, b) == plain
        for a, b in HOMOGLYPHS
    )


def _same_owner(ecosystem: str, candidate: str, original: str) -> bool:
    """Names the target's owner controls: its Maven group, Swift account or reserved NuGet prefix."""
    if ecosystem == MAVEN:
        return candidate.partition(":")[0] == original.partition(":")[0]
    if ecosystem == SWIFT:
        return candidate.lower().rsplit("/", 1)[0] == original.rsplit("/", 1)[0]
    if ecosystem == NUGET:
        prefix = candidate.split(".")[0]
        return prefix in NUGET_RESERVED and prefix == original.split(".")[0]
    return False


def _matching_popular_target(ecosystem: str, plain: str, original: str) -> TyposquatSignal | None:
    if plain == _comparable(original):
        if ecosystem not in SEPARATOR_INSENSITIVE:
            return TyposquatSignal(original, "separator confusion")
        return None

    comparable = _comparable(original)

    if _homoglyph_match(plain, comparable):
        return TyposquatSignal(original, "look-alike characters")

    if len(original) >= 5 and damerau_levenshtein(plain, comparable, 1) == 1:
        return TyposquatSignal(original, "one-character edit")

    return None


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

    if ecosystem == COCOAPODS:
        candidate = candidate.split("/")[0].lower()
        if candidate in popular:
            return None

    plain = _comparable(candidate)

    for original in popular:
        if _same_owner(ecosystem, candidate, original):
            continue
        signal = _matching_popular_target(ecosystem, plain, original)
        if signal:
            return signal

    return None
