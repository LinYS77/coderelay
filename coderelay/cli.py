from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import uvicorn

from coderelay import __version__
from coderelay.app import create_app
from coderelay.config import ConfigError, load_config
from coderelay.infra.logging import configure_logging
from coderelay.security import (
    SecretFileError,
    SecurityContext,
    generate_api_token,
    hash_api_token,
    write_secret,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="coderelay", description="Stateless verification-code resolver")
    parser.add_argument("--version", action="version", version=f"CodeRelay {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="start the HTTP service")
    _add_config_argument(serve)

    validate = subparsers.add_parser("validate-config", help="validate service config and API token hashes")
    _add_config_argument(validate)

    api_token = subparsers.add_parser("generate-api-token", help="generate a machine API token")
    api_token.add_argument("--hash-file", type=Path, help="write the token hash to this new mode-0600 file")
    return parser


def _add_config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(os.getenv("CODERELAY_CONFIG", "config.toml")),
        help="path to config.toml (default: CODERELAY_CONFIG or ./config.toml)",
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "generate-api-token":
            return _generate_api_token(args.hash_file)
        if args.command == "serve":
            return _serve(args.config)
        if args.command == "validate-config":
            return _validate_config(args.config)
    except (ConfigError, SecretFileError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


def _generate_api_token(hash_file: Path | None) -> int:
    token = generate_api_token()
    token_hash = hash_api_token(token)
    if hash_file is not None:
        write_secret(hash_file, token_hash)
        print(f"Token hash written to {hash_file.expanduser().resolve()}")
    else:
        print(f"Hash: {token_hash}")
    print("API token (shown once):")
    print(token)
    return 0


def _serve(config_path: Path) -> int:
    config = load_config(config_path)
    configure_logging(config.server.log_level)
    app = create_app(config)
    uvicorn.run(
        app,
        host=config.server.host,
        port=config.server.port,
        access_log=config.server.access_log,
        log_config=None,
        proxy_headers=True,
        forwarded_allow_ips=config.server.forwarded_allow_ips,
        server_header=False,
        workers=1,
    )
    return 0


def _validate_config(config_path: Path) -> int:
    config = load_config(config_path)
    SecurityContext.from_settings(config.security)
    print(f"Configuration is valid: {config_path.expanduser().resolve()}")
    print("- mode: stateless")
    print("- providers: totp, outlook, flysms")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
