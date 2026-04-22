import json
import sys
from pathlib import Path
import click
from rich.console import Console
from . import validate, export_json_schema
from .errors import Severity

console = Console()
err_console = Console(stderr=True)


@click.command("dialekt-validate-manifest")
@click.argument("paths", nargs=-1, required=False, type=click.Path())
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--strict", is_flag=True, help="Treat warnings as errors")
@click.option("--schema-only", is_flag=True, help="Skip security and semantic checks")
@click.option("--emit-schema", is_flag=True, help="Print JSON Schema and exit")
@click.pass_context
def main(ctx, paths, fmt, strict, schema_only, emit_schema):
    """Validate dialekt agent manifest files."""
    if emit_schema:
        click.echo(json.dumps(export_json_schema(), indent=2))
        sys.exit(0)

    if not paths:
        click.echo(ctx.get_help())
        sys.exit(2)

    all_valid = True
    results = []

    for path_str in paths:
        path = Path(path_str)
        if not path.exists():
            err_console.print(f"[red]File not found: {path}[/red]")
            sys.exit(2)

        result = validate(path, strict=strict, schema_only=schema_only)
        results.append((path, result))
        if not result.valid:
            all_valid = False

    if fmt == "json":
        output = []
        for path, result in results:
            output.append({
                "file": str(path),
                "valid": result.valid,
                "errors": [
                    {"code": i.code.value, "message": i.message, "path": i.path,
                     "line": i.line, "suggestion": i.suggestion}
                    for i in result.errors
                ],
                "warnings": [
                    {"code": i.code.value, "message": i.message, "path": i.path,
                     "line": i.line, "suggestion": i.suggestion}
                    for i in result.warnings
                ],
            })
        click.echo(json.dumps(output, indent=2))
    else:
        for path, result in results:
            _print_result(path, result)

    if all_valid:
        sys.exit(0)
    else:
        # Exit 2 if errors, 1 if only warnings
        has_errors = any(not r.valid for _, r in results)
        sys.exit(2 if has_errors else 1)


def _print_result(path: Path, result) -> None:
    manifest_name = ""
    if result.manifest:
        manifest_name = f": \"{result.manifest.metadata.name}\" ({result.manifest.metadata.version})"

    if result.valid and not result.warnings:
        console.print(f"[green]✓[/green] {path}{manifest_name}")
    elif result.valid:
        console.print(f"[yellow]✓[/yellow] {path}{manifest_name} — {len(result.warnings)} warning(s)")
        for issue in result.warnings:
            _print_issue(issue)
    else:
        console.print(f"[red]✗[/red] {path} — {len(result.errors)} error(s), {len(result.warnings)} warning(s)")
        for issue in result.errors:
            _print_issue(issue)
        for issue in result.warnings:
            _print_issue(issue)


def _print_issue(issue) -> None:
    icon = "[red]✗[/red]" if issue.is_error() else "[yellow]⚠[/yellow]"
    loc = f" line {issue.line}" if issue.line else ""
    console.print(f"  {icon} [{issue.code.value}]{loc}: {issue.message}")
    if issue.suggestion:
        console.print(f"    [dim]→ {issue.suggestion}[/dim]")


if __name__ == "__main__":
    main()
