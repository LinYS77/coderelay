from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from pathlib import Path

import httpx
import uvicorn

from coderelay import __version__
from coderelay.app import create_app
from coderelay.config import ConfigError, MicrosoftGraphSourceSettings, load_config
from coderelay.infra.logging import configure_logging
from coderelay.providers.microsoft_graph import run_device_flow
from coderelay.security import (
    SecretFileError,
    SecurityContext,
    generate_api_token,
    generate_key_material,
    hash_api_token,
    hash_ui_password,
    write_secret,
)
from coderelay.services import build_code_service


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="coderelay", description="Private verification-code relay")
    parser.add_argument("--version", action="version", version=f"CodeRelay {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="start the HTTP service")
    _add_config_argument(serve)

    validate = subparsers.add_parser("validate-config", help="validate config, secrets, and local provider state")
    _add_config_argument(validate)

    api_token = subparsers.add_parser("generate-api-token", help="generate a machine API token")
    api_token.add_argument("--hash-file", type=Path, help="write the token hash to this new mode-0600 file")

    password = subparsers.add_parser("hash-password", help="create an Argon2id UI password hash")
    password.add_argument("--output", type=Path, required=True, help="new file to receive the password hash")
    password.add_argument("--password-stdin", action="store_true", help="read one password line from stdin")

    key = subparsers.add_parser("generate-key", help="generate a session or cache encryption key")
    key.add_argument("--output", type=Path, required=True, help="new mode-0600 file to receive the key")

    outlook = subparsers.add_parser("outlook-login", help="authorize a Microsoft Graph source using device flow")
    _add_config_argument(outlook)
    outlook.add_argument("source_id", help="configured microsoft_graph source ID")

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
        if args.command == "hash-password":
            return _hash_password(args.output, args.password_stdin)
        if args.command == "generate-key":
            return _generate_key(args.output)
        if args.command == "serve":
            return _serve(args.config)
        if args.command == "validate-config":
            return asyncio.run(_validate_config(args.config))
        if args.command == "outlook-login":
            return _outlook_login(args.config, args.source_id)
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


def _hash_password(output: Path, password_stdin: bool) -> int:
    if password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("UI password: ")
        confirmation = getpass.getpass("Repeat UI password: ")
        if password != confirmation:
            raise ValueError("passwords do not match")
    password_hash = hash_ui_password(password)
    password = ""
    write_secret(output, password_hash)
    print(f"Password hash written to {output.expanduser().resolve()}")
    return 0


def _generate_key(output: Path) -> int:
    write_secret(output, generate_key_material())
    print(f"Key written to {output.expanduser().resolve()}")
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


async def _validate_config(config_path: Path) -> int:
    config = load_config(config_path)
    SecurityContext.from_settings(config.security)
    timeout = httpx.Timeout(2.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        service = build_code_service(config, client)
        try:
            statuses = service.list_sources()
        finally:
            service.close()
    print(f"Configuration is valid: {config_path.expanduser().resolve()}")
    for status in statuses:
        experimental = " (experimental)" if status.experimental else ""
        print(f"- {status.id}: {status.state.value}{experimental}")
    return 0


def _outlook_login(config_path: Path, source_id: str) -> int:
    config = load_config(config_path)
    try:
        source = config.source_by_id(source_id)
    except KeyError:
        raise ValueError(f"unknown source: {source_id}") from None
    if not isinstance(source, MicrosoftGraphSourceSettings):
        raise ValueError(f"source {source_id!r} is not a microsoft_graph source")
    print("Stop the running CodeRelay service before updating its MSAL cache.")
    username = run_device_flow(
        source,
        strict_secret_permissions=config.security.strict_secret_permissions,
        show_message=print,
    )
    print("Microsoft authorization completed successfully.")
    if username:
        print(f"Authorized account: {username}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
