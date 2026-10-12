import sys
from pathlib import Path

# Ajout automatique de la racine du projet dans sys.path pour éviter toute erreur d'import
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import argparse
from rich.console import Console
from rich.panel import Panel

# Import du moteur d'audit
from src.engine.audit_engine import audit_terraform_code

console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="DevSecOps AI Security Quality Gate - Auditeur de Conformité Terraform"
    )
    parser.add_argument(
        "--path",
        type=str,
        required=True,
        help="Chemin du fichier ou dossier Terraform à auditer",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        default=True,
        help="Bloque le pipeline CI/CD (exit code 1) si une faille [CRITICAL] est détectée",
    )

    args = parser.parse_args()
    target_path = Path(args.path)

    console.print(Panel(
        f"[bold cyan]🛡️ DEVSECOPS SECURITY QUALITY GATE[/bold cyan]\n"
        f"Cible : [yellow]{target_path}[/yellow]\n"
        f"Politique de blocage : [red]{'Active (--fail-on-critical)' if args.fail_on_critical else 'Avertissement seul'}[/red]",
        border_style="cyan"
    ))

    has_critical, report_text = audit_terraform_code(target_path)

    # Décision du Quality Gate DevSecOps
    if has_critical and args.fail_on_critical:
        console.print("\n")
        console.print(Panel(
            "[bold red]❌ SECURITY QUALITY GATE ÉCHOUÉ ![/bold red]\n\n"
            "Des violations critiques [CRITICAL] du référentiel CIS Benchmark ont été identifiées.\n"
            "⛔ [bold]Le déploiement de l'infrastructure est STRICTEMENT BLOQUÉ en CI/CD.[/bold]\n"
            "Consultez les remédiations HCL dans le rapport ci-dessus avant de fusionner votre Pull Request.",
            title="🚨 BLOCAGE CI/CD",
            border_style="bold red"
        ))
        sys.exit(1)  # Code d'erreur bloquant pour GitHub Actions
    else:
        console.print("\n")
        console.print(Panel(
            "[bold green]✔ SECURITY QUALITY GATE VALIDÉ ![/bold green]\n\n"
            "Aucune violation critique bloquante détectée.\n"
            "🚀 [bold]Déploiement de l'infrastructure autorisé.[/bold]",
            title="✅ VALIDATION CI/CD",
            border_style="bold green"
        ))
        sys.exit(0)  # Succès


if __name__ == "__main__":
    main()
