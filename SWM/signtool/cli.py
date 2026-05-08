"""
cli.py -- Command-line interface for signtool
"""

from __future__ import annotations

import glob
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Windows: enable VT100 (ANSI) mode and UTF-8 output before any Rich import
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    import ctypes
    import io
    import os

    # Enable ANSI virtual terminal on stdout/stderr
    try:
        kernel32 = ctypes.windll.kernel32
        for handle_id in (
            ctypes.c_ulong(-10),   # STD_INPUT_HANDLE  (noop)
            ctypes.c_ulong(-11),   # STD_OUTPUT_HANDLE
            ctypes.c_ulong(-12),   # STD_ERROR_HANDLE
        ):
            h = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(h, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except Exception:
        pass

    # Re-wrap stdout/stderr in UTF-8 so Rich can emit any Unicode glyph
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", newline="\n", line_buffering=True)
    if hasattr(sys.stderr, "buffer"):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", newline="\n", line_buffering=True)

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from signtool import __version__
from signtool.keygen import save_keypair
from signtool.signer import load_private_key, sign_files
from signtool.verifier import load_public_key, load_sig_file, verify_file

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _abort(message: str) -> None:
    """Print a styled error and exit with code 1."""
    err_console.print(f"\n[bold red]ERROR[/] {message}\n")
    sys.exit(1)


def _expand_globs(patterns: tuple[str, ...]) -> list[Path]:
    """Expand a list of glob patterns into a deduplicated list of Paths."""
    seen: set[Path] = set()
    result: list[Path] = []
    for pattern in patterns:
        # Try literal path first, then glob
        literal = Path(pattern)
        if literal.exists() and literal.is_file():
            p = literal.resolve()
            if p not in seen:
                seen.add(p)
                result.append(p)
        else:
            matches = sorted(glob.glob(pattern, recursive=True))
            for m in matches:
                p = Path(m).resolve()
                if p.is_file() and p not in seen:
                    seen.add(p)
                    result.append(p)
    return result


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="signtool")
def main() -> None:
    """
    \b
    signtool -- Digital File Signing CLI
    =====================================
    Sign, verify, and inspect files using RSA 2048 + SHA-256 (PKCS1v15).

    \b
    Quick start:
      signtool keygen --name mykey
      signtool sign   --key mykey_private.pem --file document.pdf
      signtool verify --key mykey_public.pem  --file document.pdf
      signtool info   document.pdf.sig
    """


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

@main.command("keygen")
@click.option(
    "--bits",
    type=click.Choice(["1024", "2048", "4096"]),
    default="2048",
    show_default=True,
    help="RSA key size in bits.",
)
@click.option(
    "--output-dir",
    "-o",
    default=".",
    show_default=True,
    type=click.Path(file_okay=False),
    help="Directory where the PEM files will be saved.",
)
@click.option(
    "--name",
    "-n",
    default="key",
    show_default=True,
    help="Base name for the output files (e.g. 'mykey' -> mykey_private.pem).",
)
@click.option(
    "--passphrase",
    "-p",
    default=None,
    hide_input=True,
    confirmation_prompt=True,
    prompt=False,
    help="Passphrase to encrypt the private key (leave empty for none).",
)
def cmd_keygen(bits: str, output_dir: str, name: str, passphrase: str | None) -> None:
    """Generate an RSA key pair and save them as PEM files."""

    bits_int         = int(bits)
    passphrase_bytes = passphrase.encode() if passphrase else None

    console.print()
    console.print(Panel(
        f"[bold cyan]Generating RSA-{bits_int} key pair[/]  [dim]-> {output_dir}[/]",
        title="[bold]signtool keygen[/]",
        border_style="cyan",
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Generating RSA-{bits_int} key pair...", total=None)
        try:
            priv_path, pub_path = save_keypair(
                bits       = bits_int,
                output_dir = output_dir,
                name       = name,
                passphrase = passphrase_bytes,
            )
        except (ValueError, OSError) as exc:
            progress.stop()
            _abort(str(exc))
        progress.update(task, description="[green]Done![/]")

    # --- Summary table ---
    table = Table(box=box.ROUNDED, border_style="cyan", show_header=True, header_style="bold cyan")
    table.add_column("Property",  style="bold", min_width=18)
    table.add_column("Value",     min_width=40)

    protected = "[green]Yes[/]" if passphrase_bytes else "[yellow]No[/] (no passphrase)"

    table.add_row("Algorithm",       f"RSA-{bits_int}")
    table.add_row("Public exponent", "65537")
    table.add_row("Private key",     str(priv_path))
    table.add_row("Public key",      str(pub_path))
    table.add_row("Passphrase",      protected)

    console.print()
    console.print(table)
    console.print()
    console.print("[bold green]Key pair generated successfully.[/]")
    console.print(
        f"\n[dim]TIP:[/] Keep [bold]{priv_path.name}[/] secret. "
        f"Distribute [bold]{pub_path.name}[/] freely.\n"
    )


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------

@main.command("sign")
@click.option(
    "--key",
    "-k",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to the RSA private key PEM file.",
)
@click.option(
    "--file",
    "-f",
    "files",
    multiple=True,
    required=True,
    help="File(s) to sign. Accepts glob patterns (e.g. 'docs/*.pdf'). Repeatable.",
)
@click.option(
    "--output-dir",
    "-o",
    default=None,
    type=click.Path(file_okay=False),
    help="Directory for .sig files. Defaults to each file's directory.",
)
@click.option(
    "--passphrase",
    "-p",
    default=None,
    help="Passphrase for an encrypted private key.",
)
def cmd_sign(key: str, files: tuple[str, ...], output_dir: str | None, passphrase: str | None) -> None:
    """Sign one or more files with an RSA private key."""

    console.print()
    console.print(Panel(
        f"[bold yellow]Signing files[/]  [dim]key -> {key}[/]",
        title="[bold]signtool sign[/]",
        border_style="yellow",
    ))

    # Load key
    passphrase_bytes = passphrase.encode() if passphrase else None
    key_path = Path(key)
    try:
        private_key = load_private_key(key_path, passphrase_bytes)
    except (FileNotFoundError, ValueError) as exc:
        _abort(str(exc))

    # Expand globs
    file_paths = _expand_globs(files)
    if not file_paths:
        _abort("No files matched the provided pattern(s).")

    out_dir = Path(output_dir) if output_dir else None

    # Sign with progress bar
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Signing...", total=len(file_paths))
        for fp in file_paths:
            progress.update(task, description=f"Signing [bold]{fp.name}[/]...")
            try:
                from signtool.signer import sign_file
                sig_path = sign_file(fp, private_key, out_dir)
                results.append((fp, sig_path, None))
            except Exception as exc:  # noqa: BLE001
                results.append((fp, None, str(exc)))
            progress.advance(task)

    # --- Summary table ---
    console.print()
    table = Table(
        box=box.ROUNDED,
        border_style="yellow",
        show_header=True,
        header_style="bold yellow",
    )
    table.add_column("File",       style="bold", min_width=24)
    table.add_column("Signature",  min_width=30)
    table.add_column("Status",     min_width=8, justify="center")

    ok_count  = 0
    err_count = 0

    for fp, sig_path, err in results:
        if err:
            err_count += 1
            table.add_row(
                str(fp.name),
                Text("-", style="dim"),
                Text("FAILED", style="bold red"),
            )
            console.print(f"  [red]Error for {fp.name}:[/] {err}")
        else:
            ok_count += 1
            table.add_row(
                str(fp.name),
                str(sig_path),
                Text("OK", style="bold green"),
            )

    console.print(table)
    console.print()

    if ok_count:
        console.print(f"[bold green]{ok_count} file(s) signed successfully.[/]")
    if err_count:
        console.print(f"[bold red]{err_count} file(s) failed.[/]")
        sys.exit(1)
    console.print()


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

@main.command("verify")
@click.option(
    "--key",
    "-k",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to the RSA public key PEM file.",
)
@click.option(
    "--file",
    "-f",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="File to verify.",
)
@click.option(
    "--sig",
    "-s",
    default=None,
    type=click.Path(dir_okay=False),
    help="Path to the .sig file. Defaults to {file}.sig.",
)
def cmd_verify(key: str, file: str, sig: str | None) -> None:
    """Verify the digital signature of a file.

    Exits with code 0 if the signature is valid, 1 otherwise.
    """

    console.print()
    console.print(Panel(
        f"[bold blue]Verifying[/]  [dim]{file}[/]",
        title="[bold]signtool verify[/]",
        border_style="blue",
    ))

    key_path  = Path(key)
    file_path = Path(file)
    sig_path  = Path(sig) if sig else None

    # Load public key
    try:
        public_key = load_public_key(key_path)
    except (FileNotFoundError, ValueError) as exc:
        _abort(str(exc))

    # Verify
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Verifying signature...", total=None)
        result = verify_file(file_path, public_key, sig_path)

    # --- Result display ---
    console.print()
    table = Table(box=box.ROUNDED, border_style="blue", show_header=True, header_style="bold blue")
    table.add_column("Property", style="bold", min_width=14, no_wrap=True)
    table.add_column("Value",    min_width=40)

    table.add_row("File",      str(result.file_path))
    table.add_row("Sig file",  str(result.sig_path))

    if result.metadata:
        m = result.metadata
        table.add_row("Algorithm",  m.algorithm)
        table.add_row("Signed at",  m.timestamp)
        table.add_row("Tool",       m.tool)
        table.add_row("SHA-256",    m.sha256[:32] + "...")
        table.add_row("Hash check", "[green]PASS[/]" if result.hash_match else "[red]FAIL[/]")

    if result.valid:
        table.add_row(
            "Signature",
            Text("VALID  [OK]", style="bold green"),
        )
    else:
        table.add_row(
            "Signature",
            Text("INVALID  [!!]", style="bold red"),
        )

    console.print(table)
    console.print()

    if result.valid:
        console.print("[bold green]Signature is VALID.[/] The file has not been tampered with.\n")
        sys.exit(0)
    else:
        err_console.print(f"[bold red]Signature is INVALID.[/]\n  Reason: {result.error}\n")
        sys.exit(1)


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

@main.command("info")
@click.argument("sig_file", type=click.Path(exists=True, dir_okay=False))
def cmd_info(sig_file: str) -> None:
    """Display metadata stored in a .sig file.

    SIG_FILE is the path to the .sig file to inspect.
    """

    sig_path = Path(sig_file)

    try:
        meta = load_sig_file(sig_path)
    except (FileNotFoundError, ValueError) as exc:
        _abort(str(exc))

    # Truncate long signature for display
    sig_preview = meta.signature[:48] + "..." if len(meta.signature) > 48 else meta.signature

    table = Table(
        box=box.ROUNDED,
        border_style="magenta",
        show_header=True,
        header_style="bold magenta",
        min_width=62,
    )
    table.add_column("Field",  style="bold", min_width=14, no_wrap=True)
    table.add_column("Value",  min_width=46)

    table.add_row("Sig file",   str(sig_path.resolve()))
    table.add_row("Format ver", str(meta.version))
    table.add_row("Tool",       meta.tool)
    table.add_row("Algorithm",  meta.algorithm)
    table.add_row("Filename",   meta.filename)
    table.add_row("Signed at",  meta.timestamp)
    table.add_row("SHA-256",    meta.sha256)
    table.add_row("Signature",  sig_preview)
    table.add_row("Sig length", f"{len(meta.signature)} chars (base64)")

    console.print()
    console.print(Panel(
        table,
        title=f"[bold magenta]Signature Metadata -- {sig_path.name}[/]",
        border_style="magenta",
        padding=(0, 1),
    ))
    console.print()
