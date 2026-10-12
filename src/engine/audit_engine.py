import os
import sys
import re
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# LlamaIndex & Qdrant
from qdrant_client import QdrantClient
from llama_index.core import VectorStoreIndex, StorageContext, Settings
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.vector_stores.qdrant import QdrantVectorStore
from llama_index.llms.ollama import Ollama

console = Console()
load_dotenv()

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "cis_benchmarks")
EMBED_MODEL_NAME = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


def init_engine():
    """Initialise le retriever Qdrant et le LLM Ollama local."""
    console.print(f"[cyan]🧠 Chargement du modèle d'embeddings ({EMBED_MODEL_NAME})...[/cyan]")
    embed_model = HuggingFaceEmbedding(model_name=EMBED_MODEL_NAME)
    Settings.embed_model = embed_model

    console.print(f"[cyan]🦙 Connexion à Ollama ({OLLAMA_BASE_URL} avec le modèle '{OLLAMA_MODEL}')...[/cyan]")
    try:
        llm = Ollama(
            model=OLLAMA_MODEL,
            base_url=OLLAMA_BASE_URL,
            request_timeout=300.0,
            temperature=0.1
        )
        Settings.llm = llm
    except Exception as e:
        console.print(f"[bold red]❌ Erreur lors de l'initialisation d'Ollama : {e}[/bold red]")
        sys.exit(1)

    client = QdrantClient(url=QDRANT_URL)
    vector_store = QdrantVectorStore(client=client, collection_name=COLLECTION_NAME)
    index = VectorStoreIndex.from_vector_store(vector_store=vector_store, embed_model=embed_model)

    return index, llm


def extract_resource_types(tf_code: str) -> list:
    """Extrait dynamiquement les types de ressources HCL présents dans le code."""
    matches = re.findall(r'resource\s+"([^"]+)"', tf_code)
    return list(set(matches))


def audit_terraform_code(file_path: Path):
    """Effectue un audit de sécurité RAG adaptatif sur n'importe quelle ressource Terraform."""
    if not file_path.exists():
        console.print(f"[bold red]❌ Fichier introuvable : {file_path}[/bold red]")
        return False, ""

    with open(file_path, "r", encoding="utf-8") as f:
        tf_code = f.read()

    # Détection dynamique des ressources (ex: aws_iam_user, aws_s3_bucket, aws_instance)
    detected_resources = extract_resource_types(tf_code)
    resources_str = ", ".join(detected_resources) if detected_resources else "AWS Resources"

    console.print(Panel(
        f"[bold yellow]Fichier analysé :[/bold yellow] {file_path.name}\n"
        f"[bold yellow]Ressources détectées :[/bold yellow] {resources_str}\n"
        f"[bold yellow]Taille :[/bold yellow] {len(tf_code.splitlines())} lignes",
        title="🔍 Cible d'Audit"
    ))

    index, llm = init_engine()

    # 1. Formulation dynamique de la requête sémantique (Routage adaptatif)
    query = f"AWS security compliance hardening best practices for {resources_str} access policies privileges and misconfigurations"
    console.print(f"[cyan]🔎 Recherche ciblée dans Qdrant : '{query}'...[/cyan]")
    
    retriever = index.as_retriever(similarity_top_k=4)
    relevant_nodes = retriever.retrieve(query)

    context_str = "\n\n---\n\n".join([node.node.get_content() for node in relevant_nodes])

    # Affichage des règles extraites
    rules_table = Table(title="Règles CIS extraites pour l'audit", show_header=True, header_style="bold green")
    rules_table.add_column("Règle ID", style="yellow", width=12)
    rules_table.add_column("Titre", style="cyan")
    for node in relevant_nodes:
        rules_table.add_row(
            node.node.metadata.get("rule_id", "N/A"),
            node.node.metadata.get("title", "N/A")
        )
    console.print(rules_table)

    # 2. Prompt d'audit strict
    prompt = f"""Tu es un Lead Cloud Security Architect. Audite ce code Terraform avec le référentiel CIS fourni.

### RÈGLES CIS OFFICIELLES APPLICABLES :
{context_str}

### CODE TERRAFORM À AUDITER :
```terraform
{tf_code}
```

### INSTRUCTIONS DE RAPPORT :
Pour chaque ressource non conforme détectée :
1. **Ressource** : nom de la ressource.
2. **Règle CIS violée** : ID exact (ex: CIS 1.16, CIS 1.20) et titre.
3. **Sévérité** : [CRITICAL] ou [HIGH].
4. **Risque** : Explication concise du danger.
5. **Remédiation HCL** : Code Terraform corrigé.
"""

    console.print("\n[bold green]🛡️ DÉBUT DU RAPPORT D'AUDIT EN DIRECT :[/bold green]\n" + "-"*80)

    full_response = ""
    try:
        response_stream = llm.stream_complete(prompt)
        for chunk in response_stream:
            print(chunk.delta, end="", flush=True)
            full_response += chunk.delta
    except Exception as e:
        console.print(f"\n[bold red]❌ Erreur lors de la génération : {e}[/bold red]")
        return False, ""

    print("\n" + "-"*80)

    # Sauvegarde
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)
    report_file = report_dir / f"audit_{file_path.stem}.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(full_response)

    console.print(f"\n[bold green]✔ Rapport complet sauvegardé dans : {report_file}[/bold green]")
    
    # Indicateur de criticité pour la CI/CD
    has_critical = "[CRITICAL]" in full_response.upper()
    return has_critical, full_response


if __name__ == "__main__":
    target = Path("data/test_iac/terragoat/terraform/aws/s3.tf")
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
    audit_terraform_code(target)
