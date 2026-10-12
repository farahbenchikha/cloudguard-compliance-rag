import os
import json
import urllib.request
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# LlamaIndex & Qdrant
from qdrant_client import QdrantClient
from llama_index.core import VectorStoreIndex, StorageContext, Document
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.vector_stores.qdrant import QdrantVectorStore

console = Console()
load_dotenv()

BENCHMARK_DIR = Path("data/benchmarks")
BENCHMARK_FILE = BENCHMARK_DIR / "cis_3.0_aws.json"
CIS_JSON_URL = "https://raw.githubusercontent.com/prowler-cloud/prowler/master/prowler/compliance/aws/cis_3.0_aws.json"

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "cis_benchmarks")
EMBED_MODEL_NAME = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")


def download_benchmark():
    """Télécharge le référentiel officiel CIS AWS Benchmark v3.0 si absent."""
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    if not BENCHMARK_FILE.exists():
        console.print(f"[cyan]🌐 Téléchargement du référentiel officiel CIS AWS v3.0 depuis Prowler...[/cyan]")
        urllib.request.urlretrieve(CIS_JSON_URL, BENCHMARK_FILE)
        console.print(f"[green]✔ Référentiel téléchargé dans {BENCHMARK_FILE}[/green]")
    else:
        console.print(f"[green]✔ Référentiel déjà présent : {BENCHMARK_FILE}[/green]")


def parse_cis_rules():
    """Parse le fichier CIS JSON et génère des Documents LlamaIndex avec métadonnées précises."""
    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    framework_name = data.get("Name", "CIS AWS Foundations Benchmark")
    requirements = data.get("Requirements", [])
    documents = []

    console.print(f"[cyan]🔍 Analyse de {len(requirements)} exigences CIS...[/cyan]")

    for req in requirements:
        rule_id = req.get("Id", "")
        title = req.get("Description", "")
        attributes = req.get("Attributes", [{}])[0] if req.get("Attributes") else {}

        section = attributes.get("Section", "Général")
        profile = attributes.get("Profile", "Level 1")
        description = attributes.get("Description", "")
        rationale = attributes.get("RationaleStatement", "")
        remediation = attributes.get("RemediationProcedure", "")
        audit = attributes.get("AuditProcedure", "")
        references = attributes.get("References", "")

        # Construction du texte sémantique enrichi pour l'embedding
        content = f"""### CIS AWS Benchmark Rule {rule_id}: {title}
**Framework**: {framework_name}
**Section**: {section}
**Profile Level**: {profile}

#### Description:
{description}

#### Rationale (Pourquoi cette règle de sécurité est critique):
{rationale}

#### Audit Procedure:
{audit}

#### Remediation (Comment corriger la faille):
{remediation}

#### Références:
{references}
""".strip()

        # Métadonnées pour filtrage et traçabilité stricte (zéro hallucination)
        metadata = {
            "rule_id": rule_id,
            "title": title,
            "section": section,
            "profile": profile,
            "framework": framework_name,
            "source": "CIS AWS Foundations Benchmark v3.0.0",
        }

        doc = Document(text=content, metadata=metadata)
        documents.append(doc)

    return documents


def run_ingestion():
    console.print("[bold blue]🚀 Démarrage du pipeline d'ingestion CIS Benchmark...[/bold blue]")

    # 1. Télécharger si nécessaire
    download_benchmark()

    # 2. Parser les règles
    documents = parse_cis_rules()
    console.print(f"[green]✔ {len(documents)} règles CIS structurées prêtes pour vectorisation.[/green]")

    # 3. Charger le modèle d'embedding (100% local HuggingFace)
    console.print(f"[cyan]🧠 Chargement du modèle d'embeddings ({EMBED_MODEL_NAME})...[/cyan]")
    embed_model = HuggingFaceEmbedding(model_name=EMBED_MODEL_NAME)

    # 4. Connexion à Qdrant
    console.print(f"[cyan]💾 Connexion à Qdrant ({QDRANT_URL})...[/cyan]")
    client = QdrantClient(url=QDRANT_URL)
    vector_store = QdrantVectorStore(client=client, collection_name=COLLECTION_NAME)
    storage_context = StorageContext.from_defaults(vector_store=vector_store)

    # 5. Création et stockage de l'index dans Qdrant
    console.print("[cyan]⚡ Génération des embeddings et indexation dans Qdrant...[/cyan]")
    index = VectorStoreIndex.from_documents(
        documents,
        storage_context=storage_context,
        embed_model=embed_model,
        show_progress=True
    )

    console.print(f"[bold green]🎉 Succès ! {len(documents)} règles CIS ont été indexées dans la collection '{COLLECTION_NAME}' ![/bold green]")

    # 6. Test d'une requête de recherche sémantique immédiate
    console.print("\n[bold magenta]🧪 Test de recherche sémantique en direct :[/bold magenta]")
    query = "S3 bucket public access and lack of encryption"
    console.print(f"[italic]Requête test : '{query}'[/italic]")
    retriever = index.as_retriever(similarity_top_k=2)
    results = retriever.retrieve(query)

    table = Table(title="Résultats de recherche dans Qdrant", show_header=True, header_style="bold cyan")
    table.add_column("Règle ID", style="yellow", width=12)
    table.add_column("Titre de la règle", style="green")
    table.add_column("Score de similarité", style="magenta", width=20)

    for res in results:
        rule_id = res.node.metadata.get("rule_id", "N/A")
        title = res.node.metadata.get("title", "N/A")
        score = f"{res.score:.4f}" if res.score is not None else "N/A"
        table.add_row(rule_id, title, score)

    console.print(table)


if __name__ == "__main__":
    run_ingestion()
